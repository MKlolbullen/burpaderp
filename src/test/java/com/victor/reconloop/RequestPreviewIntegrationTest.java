package com.victor.reconloop;

import burp.api.montoya.http.message.requests.HttpRequest;
import org.junit.Test;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.IntStream;
import static org.junit.Assert.*;

public class RequestPreviewIntegrationTest {
    private static final String URL = "https://api.example.test/search?q=original";

    @Test public void parameterPreviewAndLiveExecutionUseIdenticalMutations() {
        try (FakeMontoya fake = new FakeMontoya()) {
            var engine = new ParameterDiscoveryEngine(fake.api, IntStream.range(0,45).mapToObj(i -> "p"+i).toList());
            HttpRequest base = fake.request(URL).withHeader("Cookie","session=original");
            ScanRun run = run(20);
            var steps = materialize(engine.plan(base));
            var report = RequestPreview.inspect(run, safe(),steps);
            assertEquals(4, report.admitted()); assertEquals(3,report.conditionalAdmitted());
            assertEquals(0,run.requestBudget().used()); assertTrue(fake.sent.isEmpty());
            engine.discover(base,run,new ActiveRequestGateway(safe(),new MontoyaTargetTransport(fake.api)),0);
            assertEquals(report.admitted(),fake.sent.size());
            for (int i=0;i<steps.size();i++) {
                assertArrayEquals(steps.get(i).request().toByteArray().getBytes(),fake.sent.get(i).toByteArray().getBytes());
                assertTrue(steps.get(i).plan().matches(fake.sent.get(i)));
                assertEquals("session=original",fake.sent.get(i).headerValue("Cookie"));
            }
            assertEquals(List.of(0,20,20,5),steps.stream().map(NativeRequestStep::addedParameters).toList());
        }
    }

    @Test public void absentBaselineResponseMakesChunkEstimateAnUpperBound() {
        try (FakeMontoya fake = new FakeMontoya()) {
            var engine = new ParameterDiscoveryEngine(fake.api,List.of("hidden"));
            var report = RequestPreview.inspect(run(10),safe(),engine.plan(fake.request(URL)));
            assertEquals(2,report.admitted()); assertEquals(1,report.conditionalAdmitted());
            fake.responder = request -> null;
            engine.discover(fake.request(URL),run(10),new ActiveRequestGateway(safe(),new MontoyaTargetTransport(fake.api)),0);
            assertEquals(1,fake.sent.size());
        }
    }

    @Test public void existingParametersAreSkippedAndDeniedBaselineSkipsAllChunks() {
        try (FakeMontoya fake = new FakeMontoya()) {
            var engine = new ParameterDiscoveryEngine(fake.api,List.of("q","hidden"));
            var steps = materialize(engine.plan(fake.request(URL)));
            assertEquals(2,steps.size()); assertEquals(1,steps.get(1).addedParameters());
            assertEquals("original",steps.get(1).request().parameterValue("q"));
            var report = RequestPreview.inspect(run(10),RequestPolicy.safeDefault(url -> false),steps);
            assertEquals(0,report.admitted());
            assertEquals(RequestPolicy.DecisionCode.OUT_OF_SCOPE,report.rows().get(0).decision());
            assertEquals(RequestPolicy.DecisionCode.PREREQUISITE_DENIED,report.rows().get(1).decision());
            assertTrue(fake.sent.isEmpty());
        }
    }

    @Test public void previewUsesExistingGlobalHostEndpointAndProbeReservationsWithoutSpendingThem() {
        try (FakeMontoya fake = new FakeMontoya()) {
            for (var limits : List.of(new ScanRun.RequestLimits(2,2,2,2),new ScanRun.RequestLimits(10,2,10,10),
                    new ScanRun.RequestLimits(10,10,2,10),new ScanRun.RequestLimits(10,10,10,2))) {
                ScanRun run = ScanRun.begin(ScanProfile.ACTIVE_SAFE,ScopeSnapshot.empty(),limits);
                HttpRequest request = fake.request(URL);
                ActiveRequestGateway gateway = new ActiveRequestGateway(safe(),new MontoyaTargetTransport(fake.api));
                var step = step(request,"probe");
                assertTrue(gateway.send(run,step.plan(),request).dispatched());
                int before = fake.sent.size();
                var steps = List.of(step,step,step);
                var preview = RequestPreview.inspect(run,safe(),steps);
                assertEquals(1,run.requestBudget().used()); assertEquals(1,run.hostRequests("api.example.test"));
                assertEquals(1,run.endpointRequests("GET",URL)); assertEquals(1,run.probeRequests("probe"));
                assertEquals(before,fake.sent.size());
                for (int i=0;i<steps.size();i++) {
                    assertEquals(preview.rows().get(i).decision(),gateway.send(run,step.plan(),request).decision().code());
                }
                assertEquals(preview.admitted(),fake.sent.size()-before);
            }
        }
    }

    @Test public void previewNeverRendersCapturedPathQueryAuthenticationOrBodyValues() {
        try (FakeMontoya fake = new FakeMontoya()) {
            var request = fake.request("https://api.example.test/PATH_SECRET?token=QUERY_SECRET")
                    .withHeader("Authorization","AUTH_SECRET").withHeader("Cookie","COOKIE_SECRET").withBody("BODY_SECRET");
            var preview = RequestPreview.inspect(run(0),safe(),List.of(step(request,"probe")));
            String rendered = preview.render();
            for (String secret : List.of("PATH_SECRET","QUERY_SECRET","AUTH_SECRET","COOKIE_SECRET","BODY_SECRET")) {
                assertFalse(rendered,rendered.contains(secret)); assertFalse(preview.toString().contains(secret));
            }
            assertTrue(rendered.contains("api.example.test")); assertTrue(rendered.contains("BUDGET_EXHAUSTED"));
            assertTrue(fake.sent.isEmpty());
        }
    }

    @Test public void infiniteInputIsBoundedAndClearlyDescribedAsAPrefix() {
        try (FakeMontoya fake = new FakeMontoya()) {
            var step = step(fake.request(URL),"probe");
            AtomicInteger generated = new AtomicInteger();
            Iterable<NativeRequestStep> infinite = () -> new Iterator<>() {
                public boolean hasNext() { return true; }
                public NativeRequestStep next() { generated.incrementAndGet(); return step; }
            };
            var preview = RequestPreview.inspect(run(10),safe(),infinite);
            assertEquals(RequestPreview.MAX_STEPS,generated.get()); assertTrue(preview.truncated());
            assertTrue(preview.render().contains("prefix only")); assertTrue(fake.sent.isEmpty());
        }
    }

    @Test public void cancelledRunAndMissingPermissionsAreNotCountedAsAdmissible() {
        try (FakeMontoya fake = new FakeMontoya()) {
            ScanRun run = run(10); run.cancel();
            var cancelled = RequestPreview.inspect(run,safe(),List.of(step(fake.request(URL),"probe")));
            assertEquals(0,cancelled.admitted()); assertEquals(RequestPolicy.DecisionCode.CANCELLED,cancelled.rows().getFirst().decision());
            var denied = RequestPreview.inspect(run(10),safe(),GraphQlRequestPlanner.fuzz(fake.request(URL)));
            assertEquals(0,denied.admitted()); assertTrue(denied.render().contains("STATE_CHANGING"));
            assertTrue(denied.render().contains("UNSAFE_HTTP_METHOD")); assertTrue(fake.sent.isEmpty());
        }
    }

    @Test public void controllerPreviewsWorkWhileSendingIsDisabledAndNeverTouchHttpOrCollaborator() throws Exception {
        try (FakeMontoya fake = new FakeMontoya()) {
            ManualExecutor executor = new ManualExecutor();
            ReconController controller = ReconControllerRunLifecycleTest.controller(fake,executor);
            try {
                fake.apiAccesses.clear();
                for (var action : ReconController.PreviewAction.values()) {
                    assertTrue(controller.previewRequests(URL,action).contains("Dry run"));
                }
                assertFalse(fake.apiAccesses.contains("http")); assertFalse(fake.apiAccesses.contains("collaborator"));
                executor.runAll(); assertTrue(fake.sent.isEmpty()); assertTrue(fake.siteMap.isEmpty());
                assertTrue(controller.previewRequests("invalid",ReconController.PreviewAction.PARAMETERS).contains("No requests sent"));
                controller.setMutatingActiveRequests(true);
                controller.setActiveRequestBudget(2);
                String preview = controller.previewRequests(URL,ReconController.PreviewAction.GRAPHQL_FUZZ);
                assertTrue(preview,preview.contains("up to 2")); assertTrue(preview.contains("BUDGET_EXHAUSTED"));
            } finally { controller.shutdown(); }
        }
    }

    @Test public void controllerGraphqlExecutionMatchesTheSharedPreviewBuilders() throws Exception {
        try (FakeMontoya fake = new FakeMontoya()) {
            ManualExecutor executor = new ManualExecutor();
            ReconController controller = ReconControllerRunLifecycleTest.controller(fake,executor);
            try {
                controller.setMutatingActiveRequests(true);
                List<NativeRequestStep> expected = new ArrayList<>();
                expected.add(GraphQlRequestPlanner.introspection(fake.request(URL)));
                expected.addAll(GraphQlRequestPlanner.fuzz(fake.request(URL)));
                assertTrue(controller.previewRequests(URL,ReconController.PreviewAction.GRAPHQL_FUZZ).contains("up to 3"));
                controller.setActiveTestsEnabled(true);
                controller.introspectGraphql(URL); controller.fuzzGraphql(URL); executor.runAll();
                assertEquals(4,fake.sent.size());
                for (int i=0;i<expected.size();i++) assertTrue(expected.get(i).plan().matches(fake.sent.get(i)));
            } finally { controller.shutdown(); }
        }
    }

    private static RequestPolicy safe() { return RequestPolicy.safeDefault(url -> true); }
    private static ScanRun run(int budget) { return ScanRun.begin(ScanProfile.ACTIVE_SAFE,ScopeSnapshot.empty(),budget); }
    private static NativeRequestStep step(HttpRequest request,String probe) {
        return new NativeRequestStep(request,RequestPlan.safe(request,probe),NativeRequestStep.Mutation.PARAMETER_BASELINE,List.of(),false);
    }
    private static List<NativeRequestStep> materialize(Iterable<NativeRequestStep> steps) {
        List<NativeRequestStep> result = new ArrayList<>(); steps.forEach(result::add); return result;
    }
}
