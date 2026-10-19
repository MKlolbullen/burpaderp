package com.victor.reconloop;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import org.junit.Test;
import java.lang.reflect.InvocationTargetException;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import static org.junit.Assert.*;

public class RequestPlanIntegrationTest {
    private static final String URL = "https://api.example.test/search?q=original";

    @Test public void changedHeadersBodyMethodQueryAndPathCannotReuseAPlan() {
        try (FakeMontoya fake = new FakeMontoya()) {
            HttpRequest original = fake.request(URL).withHeader("Authorization", "Bearer original").withBody("original");
            RequestPlan plan = RequestPlan.safe(original, "test");
            ScanRun run = run();
            ActiveRequestGateway gateway = gateway(fake);
            for (HttpRequest changed : List.of(original.withHeader("Authorization", "Bearer changed"),
                    original.withHeader("Cookie", "session=changed"), original.withBody("changed"),
                    original.withMethod("POST"), original.withPath("/search?q=changed"), original.withPath("/other"))) {
                assertInvalid(gateway.send(run, plan, changed));
            }
            assertEquals(0, run.requestBudget().used()); assertTrue(fake.sent.isEmpty());
            assertTrue(gateway.send(run, plan, original).dispatched());
            assertEquals(1, fake.sent.size());
        }
    }

    @Test public void transportHostPortAndTlsAreBoundAndMustAgreeWithTheUrl() {
        try (FakeMontoya fake = new FakeMontoya()) {
            HttpRequest original = fake.request(URL);
            RequestPlan plan = RequestPlan.safe(original, "test");
            ScanRun run = run();
            ActiveRequestGateway gateway = gateway(fake);
            for (HttpService service : List.of(service("127.0.0.1",443,true), service("other.example.test",443,true),
                    service("api.example.test",8443,true), service("api.example.test",443,false))) {
                HttpRequest changed = original.withService(service);
                assertArrayEquals(original.toByteArray().getBytes(), changed.toByteArray().getBytes());
                assertInvalid(gateway.send(run, plan, changed));
                // Planning directly against a forged URL/service pair must fail too.
                assertInvalid(gateway.send(run, RequestPlan.safe(changed, "test"), changed));
            }
            assertTrue(fake.sent.isEmpty()); assertEquals(0, run.requestBudget().used());
        }
    }

    @Test public void equivalentTransportHostCaseIsAccepted() {
        try (FakeMontoya fake = new FakeMontoya()) {
            HttpRequest request = fake.request(URL).withService(service("API.EXAMPLE.TEST",443,true));
            assertTrue(gateway(fake).send(run(), RequestPlan.safe(request, "test"), request).dispatched());
        }
    }

    @Test public void missingInspectionDataFailsClosedWithoutQuota() {
        try (FakeMontoya fake = new FakeMontoya()) {
            HttpRequest request = fake.request(URL);
            for (HttpRequest broken : List.of(override(request,"toByteArray",null),
                    override(request,"httpService",null))) {
                ScanRun run = run();
                assertInvalid(gateway(fake).send(run, RequestPlan.safe(broken,"test"), broken));
                assertEquals(0, run.requestBudget().used());
            }
            assertTrue(fake.sent.isEmpty());
        }
    }

    @Test public void mismatchedMetadataAndNullPlanAreRejected() {
        try (FakeMontoya fake = new FakeMontoya()) {
            HttpRequest request = fake.request(URL);
            ScanRun run = run();
            assertInvalid(gateway(fake).send(run, RequestPlan.bind(request,
                    RequestPolicy.PlannedRequest.safe("GET",URL+"changed","test")), request));
            assertInvalid(gateway(fake).send(run, null, request));
            assertEquals(0, run.requestBudget().used()); assertTrue(fake.sent.isEmpty());
        }
    }

    @Test public void bindingUsesActualMessageBytesRatherThanTheStringRepresentation() {
        try (FakeMontoya fake = new FakeMontoya()) {
            HttpRequest original = fake.request(URL);
            HttpRequest first = override(original,"toByteArray",FakeMontoya.bytes("first\u0000wire bytes"));
            HttpRequest second = override(original,"toByteArray",FakeMontoya.bytes("second\u0000wire bytes"));
            assertEquals(first.toString(),second.toString());
            var plan = RequestPlan.safe(first,"test");
            ScanRun run = run();
            assertInvalid(gateway(fake).send(run,plan,second));
            assertEquals(0,run.requestBudget().used()); assertTrue(fake.sent.isEmpty());
            assertTrue(gateway(fake).send(run,plan,first).dispatched());
        }
    }

    @Test public void changeDuringPolicyCallbackIsDetectedBeforeTransport() {
        try (FakeMontoya fake = new FakeMontoya()) {
            HttpRequest original = fake.request(URL);
            AtomicReference<HttpRequest> current = new AtomicReference<>(original);
            HttpRequest changing = FakeMontoya.proxy(HttpRequest.class, (self, method, args) -> {
                try { return method.invoke(current.get(), args); }
                catch (InvocationTargetException e) { throw e.getCause(); }
            });
            RequestPlan plan = RequestPlan.safe(changing,"test");
            ActiveRequestGateway gateway = new ActiveRequestGateway(RequestPolicy.safeDefault(url -> {
                current.set(original.withHeader("Authorization","changed")); return true;
            }), new MontoyaTargetTransport(fake.api));
            ScanRun run = run();
            assertInvalid(gateway.send(run,plan,changing));
            assertTrue(fake.sent.isEmpty()); assertEquals(1,run.requestBudget().used());
        }
    }

    @Test public void aPreviewDoesNotAuthorizeLaterPermissionOrScopeChanges() {
        try (FakeMontoya fake = new FakeMontoya()) {
            HttpRequest request = fake.request(URL);
            var step = GraphQlRequestPlanner.introspection(request);
            var policy = new RequestPolicy(url -> true, Set.of(RequestPolicy.Permission.UNSAFE_HTTP_METHOD,
                    RequestPolicy.Permission.STATE_CHANGING));
            ScanRun run = run();
            assertEquals(1, RequestPreview.inspect(run, policy, List.of(step)).admitted());
            var denied = gateway(fake).send(run, step.plan(), step.request());
            assertEquals(RequestPolicy.DecisionCode.MISSING_PERMISSION,denied.decision().code());
            var outOfScope = new ActiveRequestGateway(new RequestPolicy(url -> false,
                    Set.of(RequestPolicy.Permission.UNSAFE_HTTP_METHOD,RequestPolicy.Permission.STATE_CHANGING)),
                    new MontoyaTargetTransport(fake.api)).send(run,step.plan(),step.request());
            assertEquals(RequestPolicy.DecisionCode.OUT_OF_SCOPE,outOfScope.decision().code());
            assertEquals(0,run.requestBudget().used()); assertTrue(fake.sent.isEmpty());
        }
    }

    private static ScanRun run() { return ScanRun.begin(ScanProfile.ACTIVE_SAFE,ScopeSnapshot.empty(),10); }
    private static ActiveRequestGateway gateway(FakeMontoya fake) {
        return new ActiveRequestGateway(RequestPolicy.safeDefault(url -> true),new MontoyaTargetTransport(fake.api));
    }
    private static void assertInvalid(ActiveRequestGateway.Result result) {
        assertFalse(result.dispatched()); assertEquals(RequestPolicy.DecisionCode.INVALID_REQUEST,result.decision().code());
    }
    private static HttpRequest override(HttpRequest request,String name,Object value) {
        return FakeMontoya.proxy(HttpRequest.class,(self,method,args) -> {
            if (method.getName().equals(name)) return value;
            try { return method.invoke(request,args); } catch (InvocationTargetException e) { throw e.getCause(); }
        });
    }
    private static HttpService service(String host,int port,boolean secure) {
        return FakeMontoya.proxy(HttpService.class,(self,method,args) -> switch (method.getName()) {
            case "host" -> host; case "port" -> port; case "secure" -> secure; default -> null;
        });
    }
}
