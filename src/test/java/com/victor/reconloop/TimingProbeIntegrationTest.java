package com.victor.reconloop;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import java.nio.file.Files;
import java.util.*;
import java.util.concurrent.atomic.*;
import static org.junit.Assert.*;

public class TimingProbeIntegrationTest {
    @Rule public TemporaryFolder folder = new TemporaryFolder();
    private static final String ROOT = "https://api.example.test";
    private static final Set<RequestPolicy.Permission> DELAY = Set.of(RequestPolicy.Permission.TIME_DELAY);
    private CorpusFuzzEngine engine(FakeMontoya fake, String corpus) throws Exception {
        Files.writeString(folder.getRoot().toPath().resolve("sqli.txt"), corpus);
        return new CorpusFuzzEngine(fake.api, new PayloadLibrary(folder.getRoot().toPath()), 0);
    }
    private ActiveRequestGateway gateway(FakeMontoya fake, AtomicLong time, Set<RequestPolicy.Permission> grants) {
        return new ActiveRequestGateway(new RequestPolicy(fake.api.scope()::isInScope, grants), fake.transport(), time::get);
    }
    private List<ActiveTestEngine.ActiveFinding> fuzz(CorpusFuzzEngine engine, FakeMontoya fake, ScanRun run, ActiveRequestGateway gateway, int localCap) {
        var request = fake.request(ROOT + "/search?q=control");
        return engine.fuzz(request, request.parameters().getFirst(), Set.of(PayloadEncoder.Encoding.RAW), localCap, run, gateway);
    }
    @Test public void gatewaySeparatesResolutionAndAdmissionFromTransportAndPersistsBothDurations() {
        try (FakeMontoya fake = new FakeMontoya()) {
            AtomicLong time = new AtomicLong();
            fake.resolver = host -> { time.addAndGet(20_000_000_000L); return List.of("93.184.216.34"); };
            fake.responder = request -> { time.addAndGet(123_456_789); return FakeMontoya.response(200,"ok",Map.of()); };
            var request = fake.request(ROOT + "/search?q=a");
            var result = gateway(fake,time,Set.of()).send(ScanRun.begin(ScanProfile.ACTIVE_SAFE,ScopeSnapshot.empty(),2),RequestPlan.safe(request,"probe"),request);
            assertEquals(123_456_789, result.transportElapsedNanos()); assertEquals(123, TimingVerification.sampleMillis(result));
            assertEquals(20_123_456_789L, result.exchange().elapsedNanos());
            assertEquals(result.transportElapsedNanos(), result.exchange().transportElapsedNanos());
            assertEquals(result.exchange().transportElapsedNanos(), result.exchange().withoutBytes().transportElapsedNanos());
        }
    }
    @Test public void corpusAlternatesThreePairsAndReproducesAStableDelayWithCompleteEvidence() throws Exception {
        try (FakeMontoya fake = new FakeMontoya()) {
            AtomicLong time = new AtomicLong();
            fake.resolver = host -> { time.addAndGet(30_000_000_000L); return List.of("93.184.216.34"); };
            fake.responder = request -> { time.addAndGet(request.parameterValue("q", burp.api.montoya.http.message.params.HttpParameterType.URL).contains("SLEEP") ? 5_100_000_000L : 100_000_000L); return FakeMontoya.response(200,"same",Map.of()); };
            var run = ScanRun.begin(ScanProfile.ACTIVE_SAFE,ScopeSnapshot.empty(),6);
            var findings = fuzz(engine(fake,"SLEEP(5)\n"),fake,run,gateway(fake,time,DELAY),6);
            assertEquals(6,fake.sent.size()); assertEquals(6,run.requestBudget().used()); assertEquals(1,findings.size());
            var finding = findings.getFirst(); assertEquals(VerificationState.REPRODUCED,finding.verificationState());
            assertEquals("2",finding.evidenceRecord().detectorVersion()); assertEquals(6,finding.evidenceRecord().exchanges().size());
            assertTrue(finding.evidenceRecord().complete()); assertTrue(finding.evidence().contains("baseline=[100, 100, 100]"));
            for (int i=0;i<6;i++) assertEquals(i%2==1, fake.sent.get(i).parameters().getFirst().value().contains("SLEEP"));
            var row = new ReconModel.ActiveRow("HIGH","CorpusFuzz-sqli","q","reproduced",finding.evidence(),ROOT,finding.evidenceRecord());
            assertEquals(List.of(row),ActiveEvidenceCodec.decode(ActiveEvidenceCodec.encode(List.of(row))).rows());
        }
    }
    @Test public void slowResolutionCannotCreateACorpusDelayAndQuotaLimitsNeverStartAHalfPair() throws Exception {
        try (FakeMontoya fake = new FakeMontoya()) {
            var engine = engine(fake,"SLEEP(5)\n");
            for (int cap : List.of(1,2,3,4,5,6,7)) {
                fake.sent.clear(); AtomicLong time = new AtomicLong(); AtomicInteger lookups = new AtomicInteger();
                fake.resolver = host -> { time.addAndGet((lookups.getAndIncrement()%2==1 ? 30L : 1L)*1_000_000_000L); return List.of("93.184.216.34"); };
                fake.responder = request -> { time.addAndGet(100_000_000L); return FakeMontoya.response(200,"same",Map.of()); };
                var run = ScanRun.begin(ScanProfile.ACTIVE_SAFE,ScopeSnapshot.empty(),cap);
                assertTrue(fuzz(engine,fake,run,gateway(fake,time,DELAY),cap).isEmpty());
                assertEquals(Math.min(6,(cap/2)*2),fake.sent.size()); assertEquals(fake.sent.size(),run.requestBudget().used());
            }
        }
    }
    @Test public void shortOrContradictorySamplesRemainCandidates() throws Exception {
        try (FakeMontoya fake = new FakeMontoya()) {
            var engine = engine(fake,"SLEEP(5)\n");
            for (int cap : List.of(2,4,6)) {
                fake.sent.clear(); AtomicLong time = new AtomicLong(); AtomicInteger n = new AtomicInteger();
                fake.responder = request -> { int i=n.getAndIncrement(); time.addAndGet(i%2==1 && (cap<6 || i==1) ? 5_100_000_000L : 100_000_000L); return FakeMontoya.response(200,"same",Map.of()); };
                var findings = fuzz(engine,fake,ScanRun.begin(ScanProfile.ACTIVE_SAFE,ScopeSnapshot.empty(),cap),gateway(fake,time,DELAY),cap);
                assertEquals(1,findings.size()); assertEquals(VerificationState.CANDIDATE,findings.getFirst().verificationState());
                assertTrue(findings.getFirst().evidence().contains("Insufficient or inconsistent"));
            }
        }
    }
    @Test public void missingResponsesRateLimitsAndFailuresCannotBeDelaySamples() throws Exception {
        try (FakeMontoya fake = new FakeMontoya()) {
            var engine = engine(fake,"SLEEP(5)\n");
            for (String failure : List.of("missing","429","500","exception")) {
                fake.sent.clear(); AtomicLong time = new AtomicLong();
                fake.responder = request -> {
                    boolean payload = request.parameters().getFirst().value().contains("SLEEP"); time.addAndGet(payload ? 10_000_000_000L : 100_000_000L);
                    if (!payload) return FakeMontoya.response(200,"same",Map.of());
                    return switch (failure) { case "missing" -> null; case "exception" -> throw new IllegalStateException("transport failure"); default -> FakeMontoya.response(Integer.parseInt(failure),"same",Map.of()); };
                };
                assertTrue(failure,fuzz(engine,fake,ScanRun.begin(ScanProfile.ACTIVE_SAFE,ScopeSnapshot.empty(),6),gateway(fake,time,DELAY),6).isEmpty());
                assertEquals(2,fake.sent.size());
            }
        }
    }
    @Test public void failedDispatchesSpendLocalCorpusQuotaAndAdmissionDenialsDoNotResolve() throws Exception {
        try (FakeMontoya fake = new FakeMontoya()) {
            var engine = engine(fake,"one\ntwo\nthree\nfour\n"); AtomicLong time = new AtomicLong();
            fake.responder = request -> { time.addAndGet(5_000_000_000L); throw new IllegalStateException("failed API attempt"); };
            var run = ScanRun.begin(ScanProfile.ACTIVE_SAFE,ScopeSnapshot.empty(),100);
            assertTrue(fuzz(engine,fake,run,gateway(fake,time,Set.of()),2).isEmpty());
            assertEquals(2,fake.sent.size()); assertEquals(2,run.requestBudget().used());
            fake.sent.clear(); fake.dnsLookups.clear(); engine = engine(fake,"SLEEP(5)\n");
            assertTrue(fuzz(engine,fake,ScanRun.begin(ScanProfile.ACTIVE_SAFE,ScopeSnapshot.empty(),6),gateway(fake,time,Set.of()),6).isEmpty());
            assertTrue(fake.sent.isEmpty()); assertTrue(fake.dnsLookups.isEmpty());
        }
    }
    @Test public void cancellationBetweenControlAndPayloadStopsLaterSends() throws Exception {
        try (FakeMontoya fake = new FakeMontoya()) {
            AtomicLong time = new AtomicLong(); var run = ScanRun.begin(ScanProfile.ACTIVE_SAFE,ScopeSnapshot.empty(),6);
            fake.onSend = request -> run.cancel();
            assertTrue(fuzz(engine(fake,"SLEEP(5)\n"),fake,run,gateway(fake,time,DELAY),6).isEmpty());
            assertEquals(1,fake.sent.size()); assertEquals(1,run.requestBudget().used());
        }
    }
    @Test public void previewCoversThreePairsAndMatchesActualQuotaBoundedMutations() throws Exception {
        try (FakeMontoya fake = new FakeMontoya()) {
            var engine = engine(fake,"SLEEP(5)\n"); var request = fake.request(ROOT+"/search?q=control");
            for (int cap : List.of(1,2,3,4,5,6,7)) {
                AtomicLong time = new AtomicLong(); fake.sent.clear(); fake.responder = r -> { time.addAndGet(100_000_000L); return FakeMontoya.response(200,"same",Map.of()); };
                var run = ScanRun.begin(ScanProfile.ACTIVE_SAFE,ScopeSnapshot.empty(),cap);
                var plan = engine.plan(request,request.parameters().getFirst(),Set.of(PayloadEncoder.Encoding.RAW),cap);
                var report = RequestPreview.inspect(run,new RequestPolicy(u->true,DELAY),plan);
                assertEquals(6,report.rows().size()); assertTrue(report.branchDependent());
                fuzz(engine,fake,run,gateway(fake,time,DELAY),cap);
                assertEquals(report.render(),report.admitted(),fake.sent.size());
                assertEquals(fake.sent.size(),run.requestBudget().used());
            }
        }
    }
    @Test public void nativeSqlTimingUsesTransportSamplesAndRejectsNullResponses() {
        try (FakeMontoya fake = new FakeMontoya()) {
            var request = fake.request(ROOT+"/search?q=control");
            for (boolean missing : List.of(false,true)) {
                AtomicLong time = new AtomicLong(); fake.sent.clear();
                fake.resolver = host -> { time.addAndGet(60_000_000_000L); return List.of("93.184.216.34"); };
                fake.responder = r -> {
                    boolean delayed = r.parameters().getFirst().value().toLowerCase(Locale.ROOT).contains("sleep");
                    time.addAndGet(delayed ? 5_100_000_000L : 100_000_000L);
                    return delayed && missing ? null : FakeMontoya.response(200,"constant body",Map.of());
                };
                var findings = new ActiveTestEngine(fake.api,0).test(request,ScanRun.begin(ScanProfile.ACTIVE_SAFE,ScopeSnapshot.empty(),100),gateway(fake,time,DELAY));
                var timing = findings.stream().filter(f -> f.testClass().equals("SQLi") && f.evidence().contains("Repeated time-based")).toList();
                assertEquals(missing?0:1,timing.size());
                if (!missing) { assertTrue(timing.getFirst().evidence().contains("baseline=[100, 100, 100]")); assertEquals("2",timing.getFirst().evidenceRecord().detectorVersion()); }
            }
        }
    }
    @Test public void eachHierarchicalLimitStopsRepeatedSamplesWithoutOvershoot() throws Exception {
        try (FakeMontoya fake = new FakeMontoya()) {
            var engine = engine(fake,"SLEEP(5)\n");
            for (var limits : List.of(new ScanRun.RequestLimits(6,3,6,6),new ScanRun.RequestLimits(6,6,3,6),new ScanRun.RequestLimits(6,6,6,3))) {
                fake.sent.clear(); AtomicLong time = new AtomicLong();
                fake.responder = r -> { time.addAndGet(r.parameters().getFirst().value().contains("SLEEP")?5_100_000_000L:100_000_000L); return FakeMontoya.response(200,"same",Map.of()); };
                var run = ScanRun.begin(ScanProfile.ACTIVE_SAFE,ScopeSnapshot.empty(),limits);
                var findings = fuzz(engine,fake,run,gateway(fake,time,DELAY),6);
                assertEquals(3,fake.sent.size()); assertEquals(3,run.requestBudget().used());
                assertEquals(VerificationState.CANDIDATE,findings.getFirst().verificationState());
                var exchanges = findings.getFirst().evidenceRecord().exchanges();
                assertFalse(exchanges.getLast().dispatchAttempted()); assertEquals(-1,exchanges.getLast().transportElapsedNanos());
            }
        }
    }
    @Test public void scopeRevocationDuringASeriesStopsBeforeTheNextResolution() throws Exception {
        try (FakeMontoya fake = new FakeMontoya()) {
            AtomicLong time = new AtomicLong(); AtomicInteger n = new AtomicInteger();
            fake.onSend = r -> { if(n.incrementAndGet()==3) fake.inScope=u->false; };
            fake.responder = r -> { time.addAndGet(r.parameters().getFirst().value().contains("SLEEP")?5_100_000_000L:100_000_000L); return FakeMontoya.response(200,"same",Map.of()); };
            var run = ScanRun.begin(ScanProfile.ACTIVE_SAFE,ScopeSnapshot.empty(),6);
            var findings = fuzz(engine(fake,"SLEEP(5)\n"),fake,run,gateway(fake,time,DELAY),6);
            assertEquals(3,fake.sent.size()); assertEquals(3,fake.dnsLookups.size());
            assertEquals(VerificationState.CANDIDATE,findings.getFirst().verificationState());
            assertEquals("OUT_OF_SCOPE",findings.getFirst().evidenceRecord().exchanges().getLast().decision());
        }
    }
    @Test public void transportFailuresRetainDurationButNeverBecomeSamplesAndDenialsHaveNoTransportTime() {
        try (FakeMontoya fake = new FakeMontoya()) {
            AtomicLong time = new AtomicLong();
            fake.responder = r -> { time.addAndGet(10_000_000_000L); throw new IllegalStateException("failed transport"); };
            var request = fake.request(ROOT+"/search?q=control");
            var run = ScanRun.begin(ScanProfile.ACTIVE_SAFE,ScopeSnapshot.empty(),2);
            var gateway = gateway(fake,time,Set.of());
            var result = gateway.send(run,RequestPlan.safe(request,"test"),request);
            assertTrue(result.dispatched()); assertEquals(10_000_000_000L,result.transportElapsedNanos());
            assertEquals(result.transportElapsedNanos(),result.exchange().transportElapsedNanos()); assertEquals(-1,TimingVerification.sampleMillis(result));
            fake.inScope=u->false;
            var denied = gateway.send(run,RequestPlan.safe(request,"test"),request);
            assertFalse(denied.dispatched()); assertEquals(-1,denied.transportElapsedNanos()); assertEquals(-1,denied.exchange().transportElapsedNanos());
            assertEquals(1,run.requestBudget().used());
        }
    }
}
