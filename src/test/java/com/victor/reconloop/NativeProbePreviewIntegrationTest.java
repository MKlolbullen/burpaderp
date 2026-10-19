package com.victor.reconloop;

import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.CollaboratorPayload;
import burp.api.montoya.http.message.requests.HttpRequest;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;
import static org.junit.Assert.*;

public class NativeProbePreviewIntegrationTest {
    @Rule public TemporaryFolder folder = new TemporaryFolder();
    private static final String ROOT = "https://api.example.test";
    private static final String CALLBACK = "real-callback.example.test";

    @Test public void allActiveDispatchesAndProbeCountsHaveRecipesAcrossRequestSurfaces() {
        try (FakeMontoya fake = new FakeMontoya()) {
            HttpRequest normal = fake.request(ROOT + "/login?q=original");
            List<HttpRequest> requests = List.of(normal,
                    normal.withMethod("POST").withHeader("Content-Type","application/json").withBody("{\"role\":\"user\"}"),
                    normal.withMethod("POST").withHeader("Content-Type","application/xml").withBody("<?xml version=\"1.0\"?><a>x</a>"),
                    normal.withMethod("POST").withHeader("Content-Type","multipart/form-data; boundary=b").withBody(uploadBody()));
            for (HttpRequest base : requests) {
                ActiveTestEngine engine = new ActiveTestEngine(fake.api,0);
                AtomicInteger callbacks = new AtomicInteger();
                engine.setCollaborator(collaborator(callbacks));
                List<NativeRequestStep> catalog = materialize(engine.plan(base,null));
                assertEquals("Planning must not allocate real OAST payloads",0,callbacks.get());
                assertTrue(fake.sent.isEmpty());
                Set<String> bytes = catalog.stream().map(step -> step.request().toString()).collect(Collectors.toSet());
                Map<String,Long> counts = catalog.stream().collect(Collectors.groupingBy(step -> step.metadata().probeId(),Collectors.counting()));
                ScanRun run = run(10000);
                engine.test(base,run,gateway(fake,EnumSet.allOf(RequestPolicy.Permission.class)));
                assertEquals(counts.toString(),catalog.size(),fake.sent.size());
                for (var count : counts.entrySet()) assertEquals(count.getKey(),count.getValue().intValue(),run.probeRequests(count.getKey()));
                for (HttpRequest sent : fake.sent) assertTrue("Unplanned mutation: " + sent.url(),bytes.contains(sent.toString().replace(CALLBACK,ActiveTestEngine.PREVIEW_CALLBACK)));
                assertTrue(callbacks.get() > 0); assertTrue(fake.errors.toString(),fake.errors.isEmpty());
                fake.sent.clear();
            }
        }
    }

    @Test public void activePreviewShowsRiskGrantsWithoutDisclosingOriginalValues() {
        try (FakeMontoya fake = new FakeMontoya()) {
            var engine = new ActiveTestEngine(fake.api,0);
            engine.setCollaborator(FakeMontoya.proxy(CollaboratorClient.class,(self,method,args) -> { throw new AssertionError("OAST allocation during preview"); }));
            HttpRequest base = fake.request(ROOT + "/PATH_SECRET?q=QUERY_SECRET").withHeader("Authorization","AUTH_SECRET")
                    .withHeader("Cookie","COOKIE_SECRET").withBody("{\"key\":\"BODY_SECRET\"}");
            ScanRun run = run(2000);
            var report = RequestPreview.inspect(run,RequestPolicy.safeDefault(url -> true),engine.plan(base,null));
            String text = report.render();
            for (String secret : List.of("PATH_SECRET","QUERY_SECRET","AUTH_SECRET","COOKIE_SECRET","BODY_SECRET")) assertFalse(text,text.contains(secret));
            assertTrue(text.contains("TIME_DELAY")); assertTrue(text.contains("OAST")); assertTrue(text.contains("PERSISTENT_PAYLOAD"));
            assertTrue(report.branchDependent()); assertTrue(text.contains("not a worst-case bound"));
            assertTrue(report.truncated()); assertEquals(0,run.requestBudget().used()); assertTrue(fake.sent.isEmpty());
            var ssrf = materialize(engine.plan(base,"ssrf"));
            assertTrue(ssrf.stream().allMatch(NativeRequestStep::template));
            for (var step : ssrf) {
                assertNull(step.plan());
                assertFalse(gateway(fake,EnumSet.allOf(RequestPolicy.Permission.class)).send(run,step.plan(),step.request()).dispatched());
            }
            assertEquals(0,run.requestBudget().used());
        }
    }

    @Test public void probeFilterCanInspectUploadAndXxeBeyondTheFullPlanPrefix() {
        try (FakeMontoya fake = new FakeMontoya()) {
            var engine = new ActiveTestEngine(fake.api,0);
            var upload = fake.request(ROOT + "/?q=x").withMethod("POST").withHeader("Content-Type","multipart/form-data; boundary=b").withBody(uploadBody());
            var uploadPlan = materialize(engine.plan(upload,"file-upload"));
            assertEquals(6,uploadPlan.size());
            assertTrue(uploadPlan.stream().allMatch(step -> step.metadata().requiredPermissions().containsAll(Set.of(RequestPolicy.Permission.UPLOAD,
                    RequestPolicy.Permission.UNSAFE_HTTP_METHOD,RequestPolicy.Permission.STATE_CHANGING))));
            String report = RequestPreview.inspect(run(20),RequestPolicy.safeDefault(url -> true),uploadPlan).render();
            assertFalse(report.contains("PRIVATE_FILENAME")); assertFalse(report.contains("FILE_BYTES_SECRET"));
            var xml = upload.withHeader("Content-Type","text/xml").withBody("<?xml version=\"1.0\"?><a>x</a>");
            var xmlPlan = materialize(engine.plan(xml,"xxe"));
            assertEquals(4,xmlPlan.size()); assertTrue(xmlPlan.getLast().template());
            assertEquals(Set.of("xxe"),xmlPlan.stream().map(step -> step.metadata().probeId()).collect(Collectors.toSet()));
        }
    }

    @Test public void corpusPreviewMatchesEncodingsAndLocalCapsAcrossParametersAndTargets() throws Exception {
        Files.writeString(folder.newFile("sqli.txt").toPath(),"alpha\nbeta\ngamma\n");
        try (FakeMontoya fake = new FakeMontoya()) {
            var engine = new CorpusFuzzEngine(fake.api,new PayloadLibrary(folder.getRoot().toPath()),0);
            var selected = EnumSet.of(PayloadEncoder.Encoding.RAW,PayloadEncoder.Encoding.BASE64);
            ScanRun run = run(100);
            List<NativeRequestStep> steps = new ArrayList<>();
            List<HttpRequest> targets = List.of(fake.request(ROOT + "/?q=a&r=b"),fake.request("https://other.example.test/?q=c"));
            for (HttpRequest base : targets) for (var parameter : base.parameters()) steps.addAll(materialize(engine.plan(base,parameter,selected,3)));
            var report = RequestPreview.inspect(run,new RequestPolicy(url -> true,Set.of()),steps);
            assertEquals(9,report.admitted()); assertEquals(0,run.requestBudget().used());
            assertTrue(report.rows().stream().anyMatch(row -> row.decision() == RequestPolicy.DecisionCode.LOCAL_BUDGET_EXHAUSTED));
            for (HttpRequest base : targets) for (var parameter : base.parameters()) engine.fuzz(base,parameter,selected,3,run,gateway(fake,Set.of()));
            assertEquals(report.admitted(),fake.sent.size());
            Set<String> planned = steps.stream().map(step -> step.request().toString()).collect(Collectors.toSet());
            assertTrue(fake.sent.stream().allMatch(request -> planned.contains(request.toString())));
            assertTrue(fake.errors.toString(),fake.errors.isEmpty());
        }
    }

    @Test public void timingPairsRequireTwoGlobalAndLocalTokensAndAMatchingBaselineAdmission() throws Exception {
        Files.writeString(folder.newFile("sqli.txt").toPath(),"SLEEP(5)\nplain\n");
        try (FakeMontoya fake = new FakeMontoya()) {
            var engine = new CorpusFuzzEngine(fake.api,new PayloadLibrary(folder.getRoot().toPath()),0);
            var request = fake.request(ROOT + "/?q=a"); var parameter = request.parameters().getFirst();
            var grants = Set.of(RequestPolicy.Permission.TIME_DELAY);
            for (int cap : List.of(1,2,3)) {
                ScanRun run = run(cap);
                var report = RequestPreview.inspect(run,new RequestPolicy(url -> true,grants),engine.plan(request,parameter,Set.of(PayloadEncoder.Encoding.RAW),cap));
                assertEquals(0,run.requestBudget().used());
                engine.fuzz(request,parameter,Set.of(PayloadEncoder.Encoding.RAW),cap,run,gateway(fake,grants));
                assertEquals(report.admitted(),fake.sent.size()); fake.sent.clear();
            }
            var denied = RequestPreview.inspect(run(10),RequestPolicy.safeDefault(url -> true),engine.plan(request,parameter,Set.of(PayloadEncoder.Encoding.RAW),3));
            assertEquals(RequestPolicy.DecisionCode.MISSING_PERMISSION,denied.rows().get(0).decision());
            assertEquals(RequestPolicy.DecisionCode.PREREQUISITE_DENIED,denied.rows().get(1).decision());
            assertEquals(1,denied.admitted());
        }
    }

    @Test public void callbackCorpusTemplatesAreNeverBoundAndDestructiveEntriesAreAbsent() throws Exception {
        Files.writeString(folder.newFile("rce.txt").toPath(),"?cmd={payload}\n");
        Files.writeString(folder.newFile("rce_payloads.txt").toPath(),"net user injected /add\ncurl https://foreign.example.test/path\n");
        try (FakeMontoya fake = new FakeMontoya()) {
            var engine = new CorpusFuzzEngine(fake.api,new PayloadLibrary(folder.getRoot().toPath()),0);
            engine.setCollaborator(FakeMontoya.proxy(CollaboratorClient.class,(self,method,args) -> { throw new AssertionError("OAST during preview"); }));
            var request = fake.request(ROOT + "/?cmd=x");
            var steps = materialize(engine.plan(request,request.parameters().getFirst(),Set.of(PayloadEncoder.Encoding.BASE64),5));
            assertEquals(1,steps.size()); assertTrue(steps.getFirst().template()); assertNull(steps.getFirst().plan());
            var report = RequestPreview.inspect(run(10),new RequestPolicy(url -> true,Set.of(RequestPolicy.Permission.OAST)),steps);
            assertEquals(0,report.admitted()); assertEquals(1,report.runtimeTemplates());
            assertEquals(RequestPolicy.DecisionCode.PENDING_BINDING,report.rows().getFirst().decision());
            assertFalse(report.render().contains("foreign.example.test")); assertTrue(fake.sent.isEmpty());
        }
    }

    @Test public void responseDependentScenarioDoesNotClaimToBeTheWorstCaseDispatchCount() {
        try (FakeMontoya fake = new FakeMontoya()) {
            var a = recipe(fake.request("https://a.example.test/"),"p1");
            var b = recipe(fake.request("https://a.example.test/other"),"p2");
            var c = recipe(fake.request("https://b.example.test/"),"p1");
            ScanRun run = ScanRun.begin(ScanProfile.ACTIVE_SAFE,ScopeSnapshot.empty(),new ScanRun.RequestLimits(2,1,2,1));
            var report = RequestPreview.inspect(run,RequestPolicy.safeDefault(url -> true),List.of(a,b,c));
            assertEquals(1,report.admitted());
            // Taking a different response branch can fit two sends, despite the greedy scenario fitting one.
            assertTrue(gateway(fake,Set.of()).send(run,b.plan(),b.request()).dispatched());
            assertTrue(gateway(fake,Set.of()).send(run,c.plan(),c.request()).dispatched());
            assertTrue(report.render().contains("not a worst-case bound"));
        }
    }

    @Test public void deniedBaselinesSkipDependentSqlNoSqlTraversalAndXmlCandidates() {
        try (FakeMontoya fake = new FakeMontoya()) {
            var base = fake.request(ROOT + "/?q=original");
            var engine = new ActiveTestEngine(fake.api,0);
            RequestPolicy policy = new RequestPolicy(url -> !url.contains("original"),EnumSet.allOf(RequestPolicy.Permission.class));
            for (String probe : List.of("sqli","nosqli","path-traversal","xxe")) {
                var request = probe.equals("xxe") ? base.withHeader("Content-Type","text/xml").withBody("<?xml version=\"1.0\"?><a>x</a>") : base;
                var report = RequestPreview.inspect(run(1000),policy,engine.plan(request,probe));
                assertEquals(probe,0,report.admitted());
                assertTrue(probe,report.rows().stream().anyMatch(row -> row.decision() == RequestPolicy.DecisionCode.PREREQUISITE_DENIED));
            }
            assertTrue(fake.sent.isEmpty());
        }
    }

    @Test public void runtimeTemplateScopeIsPendingAndCannotAuthorizeALiveDispatch() {
        try (FakeMontoya fake = new FakeMontoya()) {
            var base = fake.request(ROOT + "/?q=x");
            var step = new ActiveTestEngine(fake.api,0).plan(base,"ssrf").iterator().next();
            AtomicInteger scopeChecks = new AtomicInteger();
            var policy = new RequestPolicy(url -> { scopeChecks.incrementAndGet(); return false; },Set.of(RequestPolicy.Permission.OAST));
            ScanRun run = run(10);
            var report = RequestPreview.inspect(run,policy,List.of(step));
            assertEquals(RequestPolicy.DecisionCode.PENDING_BINDING,report.rows().getFirst().decision());
            assertEquals(0,scopeChecks.get()); assertEquals(0,report.admitted());
            var gateway = new ActiveRequestGateway(policy,fake.transport());
            assertEquals(RequestPolicy.DecisionCode.INVALID_REQUEST,gateway.send(run,step.plan(),step.request()).decision().code());
            var rebound = RequestPlan.bind(step.request(),step.metadata());
            assertEquals(RequestPolicy.DecisionCode.OUT_OF_SCOPE,gateway.send(run,rebound,step.request()).decision().code());
            assertEquals(1,scopeChecks.get()); assertEquals(0,run.requestBudget().used()); assertTrue(fake.sent.isEmpty());
        }
    }

    @Test public void boundedPrefixDoesNotBuildUnvisitedRequestLevelRecipes() {
        try (FakeMontoya fake = new FakeMontoya()) {
            var base = fake.request(ROOT + "/?q=x");
            AtomicInteger reads = new AtomicInteger();
            HttpRequest counted = FakeMontoya.proxy(HttpRequest.class,(self,method,args) -> {
                if (method.getName().equals("bodyToString")) reads.incrementAndGet();
                try { return method.invoke(base,args); }
                catch (java.lang.reflect.InvocationTargetException e) { throw e.getCause(); }
            });
            var report = RequestPreview.inspect(run(20),RequestPolicy.safeDefault(url -> true),new ActiveTestEngine(fake.api,0).plan(counted,null));
            assertTrue(report.truncated());
            assertEquals("Only insertion-point enumeration should inspect the base body in this prefix",1,reads.get());
            assertTrue(fake.sent.isEmpty());
        }
    }

    private static NativeRequestStep recipe(HttpRequest request,String probe) {
        return new NativeRequestRecipe(() -> request,probe,Set.of(),NativeRequestStep.Mutation.ACTIVE_VALUE,
                NativeRequestStep.Condition.RESPONSE_BRANCH,"candidate",false).build();
    }
    static String uploadBody() {
        return "--b\r\nContent-Disposition: form-data; name=\"file\"; filename=\"PRIVATE_FILENAME.jpg\"\r\nContent-Type: image/jpeg\r\n\r\nFILE_BYTES_SECRET\r\n--b--\r\n";
    }
    static CollaboratorClient collaborator(AtomicInteger allocations) {
        return FakeMontoya.proxy(CollaboratorClient.class,(self,method,args) -> {
            if (!method.getName().equals("generatePayload")) return null;
            allocations.incrementAndGet();
            return FakeMontoya.proxy(CollaboratorPayload.class,(p,call,values) -> call.getName().equals("toString") ? CALLBACK : null);
        });
    }
    static ScanRun run(int cap) { return ScanRun.begin(ScanProfile.ACTIVE_SAFE,ScopeSnapshot.empty(),cap); }
    static ActiveRequestGateway gateway(FakeMontoya fake,Set<RequestPolicy.Permission> grants) {
        return new ActiveRequestGateway(new RequestPolicy(url -> true,grants),fake.transport());
    }
    static List<NativeRequestStep> materialize(Iterable<NativeRequestStep> plan) {
        List<NativeRequestStep> result = new ArrayList<>(); plan.forEach(result::add); return result;
    }
}
