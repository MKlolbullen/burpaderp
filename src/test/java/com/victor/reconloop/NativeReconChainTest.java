package com.victor.reconloop;

import org.junit.Test;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.Assert.*;

public class NativeReconChainTest {
    static DomainReconProcess.Plan plan(int budget,int depth)throws Exception{
        Path dir=Files.createTempDirectory("native-recon");String id=UUID.randomUUID().toString();
        var plan=new DomainReconProcess.Plan("example.com","reconctl",dir,id,20,5,true,100, budget,depth);
        Files.createDirectories(plan.runDir());return plan;
    }
    static ScanRun run(DomainReconProcess.Plan plan){return ScanRun.begin(ScanProfile.DISCOVERY,ScopeSnapshot.forTargetUrl("https://example.com/"),new ScanRun.RequestLimits(plan.httpBudget(),plan.perHost(),3,plan.httpBudget()));}
    static NativeReconChain.Inputs inputs(){return new NativeReconChain.Inputs(List.of("example.com"),List.of(),Map.of());}

    @Test public void oneLedgerCoversProbeCrawlJsAndEvidenceWithNoNPlusOneDispatch()throws Exception{
        try(var fake=new FakeMontoya()){
            var plan=plan(3,3);var run=run(plan);
            fake.responder=request->FakeMontoya.response(200,request.pathWithoutQuery().equals("/")?"<title>Fixture</title><script src='/app.js'></script><a href='/next'>next</a>":"fetch('/api/data?z=%2f&a=+');",Map.of("Content-Type",request.pathWithoutQuery().endsWith(".js")?"application/javascript":"text/html","Server","fixture-server"));
            var gateway=new ActiveRequestGateway(RequestPolicy.safeDefault(fake.inScope),fake.transport());
            var outcome=new NativeReconChain(gateway,fake::request).run(plan,inputs(),run,e->{});
            assertEquals(3,fake.sent.size());assertEquals(3,outcome.dispatched());assertEquals(3,run.requestBudget().used());assertEquals("PARTIAL",outcome.state());
            assertTrue(fake.sent.stream().allMatch(r->r.method().equals("GET")&&r.httpService().host().equals("93.184.216.34")));
            String evidence=Files.readString(plan.runDir().resolve("native/evidence.jsonl"));assertTrue(evidence.contains("plannedRequest"));assertTrue(evidence.contains("SIGNAL"));assertTrue(evidence.contains(plan.runId()));
            String metadata=Files.readString(plan.runDir().resolve("native/http.jsonl"));assertTrue(metadata.contains("fixture-server"));assertTrue(metadata.contains("Fixture"));
            assertTrue(Files.readString(plan.runDir().resolve("native/urls.jsonl")).contains("/api/data?z=%2f"));
            assertTrue(ReconWorkflowInputs.review(plan).stream().anyMatch(s->s.kind()==AiAnalysis.Kind.JAVASCRIPT));
            if(Files.getFileStore(plan.runDir()).supportsFileAttributeView("posix"))assertEquals("rw-------",java.nio.file.attribute.PosixFilePermissions.toString(Files.getPosixFilePermissions(plan.runDir().resolve("native/evidence.jsonl"))));
        }
    }

    @Test public void redirectHopRechecksCurrentScopeAndProtectedResolvedDestination()throws Exception{
        for(boolean protectedAddress:List.of(false,true))try(var fake=new FakeMontoya()){
            var plan=plan(10,2);var run=run(plan);
            fake.inScope=url->protectedAddress||!url.contains("api.example.com");
            fake.resolver=host->List.of(protectedAddress&&host.equals("api.example.com")?"127.0.0.1":"93.184.216.34");
            fake.responder=request->FakeMontoya.response(302,"",Map.of("Location","https://api.example.com/next"));
            var outcome=new NativeReconChain(new ActiveRequestGateway(RequestPolicy.safeDefault(fake.inScope),fake.transport()),fake::request).run(plan,inputs(),run,e->{});
            assertEquals(1,fake.sent.size());assertEquals(1,outcome.denied());assertEquals(1,outcome.dispatched());
            assertTrue(Files.readString(plan.runDir().resolve("native/http.jsonl")).contains(protectedAddress?"PROTECTED_DESTINATION":"OUT_OF_SCOPE"));
        }
    }

    @Test public void cancellationAfterFirstSendCannotStartAFreshBudgetOrSecondStage()throws Exception{
        try(var fake=new FakeMontoya()){
            var plan=plan(20,3);var run=run(plan);fake.onSend=request->run.cancel();
            fake.responder=request->FakeMontoya.response(200,"<script src='/app.js'></script>",Map.of("Content-Type","text/html"));
            var outcome=new NativeReconChain(new ActiveRequestGateway(RequestPolicy.safeDefault(fake.inScope),fake.transport()),fake::request).run(plan,inputs(),run,e->{});
            assertEquals("CANCELLED",outcome.state());assertEquals(1,fake.sent.size());assertEquals(1,run.requestBudget().used());
        }
    }

    @Test public void httpsTransportFallbackChargesSameGlobalAndHostLedger()throws Exception{
        try(var fake=new FakeMontoya()){
            var plan=plan(2,0);var run=run(plan);AtomicInteger sends=new AtomicInteger();
            var gateway=new ActiveRequestGateway(RequestPolicy.safeDefault(fake.inScope),request->{if(sends.incrementAndGet()==1)throw new java.io.IOException("fixture TLS failure");return FakeMontoya.pair(request,FakeMontoya.response(200,"ok",Map.of()));});
            var outcome=new NativeReconChain(gateway,fake::request).run(plan,inputs(),run,e->{});
            assertEquals(2,sends.get());assertEquals(2,outcome.dispatched());assertEquals(2,run.hostRequests("example.com"));assertEquals(1,outcome.responses());
            assertTrue(Files.readString(plan.runDir().resolve("native/http.jsonl")).contains("http://example.com/"));
        }
    }

    @Test public void existingNativeOutputDirectoryPreventsRepeatExecutionAndOverwrite()throws Exception{
        try(var fake=new FakeMontoya()){
            var plan=plan(3,1);var gateway=new ActiveRequestGateway(RequestPolicy.safeDefault(fake.inScope),fake.transport());
            var chain=new NativeReconChain(gateway,fake::request);chain.run(plan,inputs(),run(plan),e->{});
            String before=Files.readString(plan.runDir().resolve("native/summary.json"));int sent=fake.sent.size();
            assertEquals("FAILED",chain.run(plan,inputs(),run(plan),e->{}).state());assertEquals(sent,fake.sent.size());assertEquals(before,Files.readString(plan.runDir().resolve("native/summary.json")));
        }
    }

    @Test public void urlCanonicalisationAndJsExtractionPreserveRequestSemantics(){
        String value="HTTPS://WWW.Example.COM:443/a%2Fb/../c?b=%2f&a=+&a=%20#fragment";
        assertEquals("https://www.example.com/a%2Fb/../c?b=%2f&a=+&a=%20",NativeReconChain.canonical(value,"example.com"));
        assertEquals(Set.of("https://www.example.com/api/a%2Fb?z=2&a=1"),NativeReconChain.extract("https://www.example.com/app.js","fetch('/api/a%2Fb?z=2&a=1');fetch('https://evil-example.com/x');", "example.com"));
        for(String invalid:List.of("https://user:pass@example.com/","https://127.0.0.1/","https://evil-example.com/","javascript:alert(1)","https://example.com:99999/"))assertNull(NativeReconChain.canonical(invalid,"example.com"));
    }

    @Test public void perHostQuotaDoesNotResetBetweenProbeAndCrawl()throws Exception{
        try(var fake=new FakeMontoya()){
            var original=plan(5,3);var plan=new DomainReconProcess.Plan(original.domain(),original.executable(),original.outputDir(),original.runId(),20,5,true,100,5,3,1);
            fake.responder=request->FakeMontoya.response(200,"<script src='/app.js'></script><a href='/next'>next</a>",Map.of("Content-Type","text/html"));
            var result=new NativeReconChain(new ActiveRequestGateway(RequestPolicy.safeDefault(fake.inScope),fake.transport()),fake::request).run(plan,inputs(),run(plan),e->{});
            assertEquals(1,result.dispatched());assertEquals(1,fake.sent.size());assertEquals(2,result.denied());
            assertTrue(Files.readString(plan.runDir().resolve("native/http.jsonl")).contains("HOST_BUDGET_EXHAUSTED"));
        }
    }

    @Test public void workflowArtifactsAreCorrelatedAndRejectedBeforeAnyNativeWork()throws Exception{
        var plan=plan(3,1);
        Files.writeString(plan.runDir().resolve("hosts.jsonl"),"{\"kind\":\"hostname\",\"value\":\"outside.test\",\"run_id\":\""+plan.runId()+"\"}\n");
        Files.writeString(plan.runDir().resolve("dns.jsonl"),"");Files.writeString(plan.runDir().resolve("urls.jsonl"),"");
        assertThrows(java.io.IOException.class,()->ReconWorkflowInputs.load(plan));
    }
}
