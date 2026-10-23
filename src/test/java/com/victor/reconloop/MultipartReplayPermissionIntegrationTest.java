package com.victor.reconloop;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.lang.reflect.InvocationTargetException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

import static org.junit.Assert.*;

public class MultipartReplayPermissionIntegrationTest {
    private static final String URL = "https://api.example.test/upload?q=a";
    private static final String BODY = "--b\r\nContent-Disposition: form-data; name=\"file\"; filename=\"fixture.txt\"\r\n"
            + "Content-Type: text/plain\r\n\r\nfixture bytes\r\n--b--\r\n";
    @Rule public TemporaryFolder folder = new TemporaryFolder();

    @Test public void everyBindingEntryPointRequiresUploadForMultipartRegardlessOfProbeOrMethod() {
        for (String method : List.of("GET", "POST")) for (String type : List.of(
                "multipart/form-data; boundary=b", "multipart/mixed; boundary=b", "  MuLtIpArT/FoRm-DaTa; boundary=b")) {
            try (var fake = new FakeMontoya()) {
                HttpRequest request = fake.request(URL).withMethod(method).withHeader("Content-Type", type).withBody(BODY);
                var methodGrants = method.equals("GET") ? EnumSet.noneOf(RequestPolicy.Permission.class)
                        : EnumSet.of(RequestPolicy.Permission.UNSAFE_HTTP_METHOD, RequestPolicy.Permission.STATE_CHANGING);
                for (RequestPlan plan : List.of(RequestPlan.safe(request, "cors"),
                        RequestPlan.create(request, "sqli", Set.of()),
                        RequestPlan.bind(request, RequestPolicy.PlannedRequest.safe(method, URL, "jwt")))) {
                    assertTrue(plan.matches(request));
                    assertTrue(plan.policyRequest().requiredPermissions().contains(RequestPolicy.Permission.UPLOAD));
                    var deniedRun = run();
                    var denied = gateway(fake, methodGrants).send(deniedRun, plan, request);
                    assertEquals(RequestPolicy.DecisionCode.MISSING_PERMISSION, denied.decision().code());
                    assertEquals(Set.of(RequestPolicy.Permission.UPLOAD), denied.decision().missingPermissions());
                    assertFalse(denied.dispatched()); assertEquals(0, deniedRun.requestBudget().used());
                    assertTrue(fake.sent.isEmpty()); assertTrue(fake.dnsLookups.isEmpty());
                }
                methodGrants.add(RequestPolicy.Permission.UPLOAD);
                var allowedRun = run();
                var allowed = gateway(fake, methodGrants).send(allowedRun, RequestPlan.safe(request, "cors"), request);
                assertTrue(allowed.dispatched()); assertEquals(1, allowedRun.requestBudget().used());
                assertEquals(1, fake.sent.size()); assertEquals(BODY, fake.sent.getFirst().bodyToString());
            }
        }
    }

    @Test public void uploadPermissionDoesNotGrantUnsafeMethodPermission() {
        try (var fake = new FakeMontoya()) {
            var request = fake.request(URL).withMethod("POST").withHeader("Content-Type", "multipart/form-data; boundary=b").withBody(BODY);
            var run = run();
            var denied = gateway(fake, Set.of(RequestPolicy.Permission.UPLOAD)).send(run, RequestPlan.safe(request, "cors"), request);
            assertEquals(Set.of(RequestPolicy.Permission.UNSAFE_HTTP_METHOD), denied.decision().missingPermissions());
            assertTrue(fake.sent.isEmpty()); assertTrue(fake.dnsLookups.isEmpty()); assertEquals(0, run.requestBudget().used());
        }
    }

    @Test public void aLaterMultipartContentTypeCannotHideBehindABenignFirstHeader() {
        try (var fake = new FakeMontoya()) {
            var request = duplicateContentType(fake.request(URL).withHeader("Content-Type", "multipart/form-data; boundary=b").withBody(BODY));
            assertEquals("application/json", request.headerValue("Content-Type"));
            var run = run();
            var denied = gateway(fake, Set.of()).send(run, RequestPlan.safe(request, "generic"), request);
            assertEquals(Set.of(RequestPolicy.Permission.UPLOAD), denied.decision().missingPermissions());
            assertTrue(fake.sent.isEmpty()); assertTrue(fake.dnsLookups.isEmpty()); assertEquals(0, run.requestBudget().used());
        }
    }

    @Test public void missingHeaderInspectionFailsClosedButOrdinaryJsonNeedsNoUploadGrant() {
        try (var fake = new FakeMontoya()) {
            var json = fake.request(URL).withHeader("Content-Type", "application/json").withBody("{}");
            HttpRequest unknown = FakeMontoya.proxy(HttpRequest.class, (self, method, args) -> {
                if (method.getName().equals("headers")) return null;
                try { return method.invoke(json, args); }
                catch (InvocationTargetException error) { throw error.getCause(); }
            });
            var run = run();
            var denied = gateway(fake, Set.of()).send(run, RequestPlan.safe(unknown, "generic"), unknown);
            assertEquals(RequestPolicy.DecisionCode.INVALID_REQUEST, denied.decision().code());
            assertTrue(fake.sent.isEmpty()); assertTrue(fake.dnsLookups.isEmpty()); assertEquals(0, run.requestBudget().used());
            assertTrue(gateway(fake, Set.of()).send(run, RequestPlan.safe(json, "generic"), json).dispatched());
            assertEquals(1, fake.sent.size());
        }
    }

    @Test public void corpusPreviewAndExecutionRequireUploadEvenWhenOnlyTheQueryChanges() throws Exception {
        Files.writeString(folder.newFile("sqli.txt").toPath(), "marker\n");
        try (var fake = new FakeMontoya()) {
            var engine = new CorpusFuzzEngine(fake.api, new PayloadLibrary(folder.getRoot().toPath()), 0);
            var request = fake.request(URL).withMethod("POST").withHeader("Content-Type", "multipart/form-data; boundary=b").withBody(BODY);
            var parameter = request.parameters().getFirst();
            var encodings = Set.of(PayloadEncoder.Encoding.RAW);
            var steps = NativeProbePreviewIntegrationTest.materialize(engine.plan(request, parameter, encodings, 1));
            assertEquals(1, steps.size());
            var grants = EnumSet.of(RequestPolicy.Permission.UNSAFE_HTTP_METHOD, RequestPolicy.Permission.STATE_CHANGING);
            var deniedRun = run();
            var report = RequestPreview.inspect(deniedRun, new RequestPolicy(url -> true, grants), steps);
            assertEquals(0, report.admitted());
            assertEquals("UPLOAD", report.rows().getFirst().missingPermissions());
            engine.fuzz(request, parameter, encodings, 1, deniedRun, gateway(fake, grants));
            assertTrue(fake.sent.isEmpty()); assertTrue(fake.dnsLookups.isEmpty()); assertEquals(0, deniedRun.requestBudget().used());
            grants.add(RequestPolicy.Permission.UPLOAD);
            var allowedRun = run();
            assertEquals(1, RequestPreview.inspect(allowedRun, new RequestPolicy(url -> true, grants), steps).admitted());
            assertEquals(0, allowedRun.requestBudget().used());
            engine.fuzz(request, parameter, encodings, 1, allowedRun, gateway(fake, grants));
            assertEquals(1, fake.sent.size()); assertEquals(BODY, fake.sent.getFirst().bodyToString());
            assertEquals(1, allowedRun.requestBudget().used());
        }
    }

    private static ScanRun run() { return ScanRun.begin(ScanProfile.ACTIVE_MUTATION, ScopeSnapshot.empty(), 10); }
    private static ActiveRequestGateway gateway(FakeMontoya fake, Set<RequestPolicy.Permission> grants) {
        return new ActiveRequestGateway(new RequestPolicy(url -> true, grants), fake.transport());
    }
    private static HttpRequest duplicateContentType(HttpRequest original) {
        var headers = new ArrayList<HttpHeader>();
        headers.add(HttpHeader.httpHeader("Content-Type", "application/json")); headers.addAll(original.headers());
        String wire = original.toString().replace("\r\nContent-Type:", "\r\nContent-Type: application/json\r\nContent-Type:");
        return FakeMontoya.proxy(HttpRequest.class, (self, method, args) -> {
            if (method.getName().equals("headers")) return List.copyOf(headers);
            if (method.getName().equals("headerValue") && ((String) args[0]).equalsIgnoreCase("Content-Type")) return "application/json";
            if (method.getName().equals("toByteArray")) return FakeMontoya.bytes(wire);
            if (method.getName().equals("toString")) return wire;
            if (method.getName().equals("withService")) return duplicateContentType(original.withService((HttpService) args[0]));
            try { return method.invoke(original, args); }
            catch (InvocationTargetException error) { throw error.getCause(); }
        });
    }
}
