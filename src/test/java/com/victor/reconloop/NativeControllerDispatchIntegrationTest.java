package com.victor.reconloop;

import org.junit.Test;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import static org.junit.Assert.*;

public class NativeControllerDispatchIntegrationTest {
    private static final String ROOT = "https://api.example.test";

    @Test public void graphqlAndParameterDiscoveryRespectTheirWholeJobCaps() throws Exception {
        try (FakeMontoya fake = new FakeMontoya()) {
            ManualExecutor executor = new ManualExecutor();
            ReconController controller = ReconControllerRunLifecycleTest.controller(fake, executor);
            try {
                controller.setActiveTestsEnabled(true); controller.setMutatingActiveRequests(true);
                controller.setActiveRequestBudget(2);
                controller.fuzzGraphql(ROOT + "/graphql"); executor.runAll();
                assertEquals(2, fake.sent.size());
                assertTrue(fake.sent.stream().allMatch(r -> r.method().equals("POST")));
                fake.sent.clear();
                controller.introspectGraphql(ROOT + "/graphql"); executor.runAll();
                assertEquals(1, fake.sent.size());
                fake.sent.clear();
                controller.discoverParameters(ROOT + "/search"); executor.runAll();
                assertEquals(2, fake.sent.size());
                assertTrue(fake.sent.stream().allMatch(r -> r.method().equals("GET")));
                assertTrue(fake.errors.toString(), fake.errors.isEmpty());
            } finally { controller.shutdown(); }
        }
    }

    @Test public void alternateIdentityNeedsAuthGrantAndUsesTheTransport() throws Exception {
        try (FakeMontoya fake = new FakeMontoya()) {
            ManualExecutor executor = new ManualExecutor();
            ReconController controller = ReconControllerRunLifecycleTest.controller(fake, executor);
            try {
                var privileged = fake.request(ROOT + "/account").withUpdatedHeader("Authorization", "Bearer test-token");
                fake.siteMap.add(FakeMontoya.pair(privileged, FakeMontoya.response(200, "private", Map.of())));
                fake.responder = request -> FakeMontoya.response(403, "denied", Map.of());
                controller.setActiveTestsEnabled(true);
                controller.runAccessControlTest("", true); executor.runAll(); assertTrue(fake.sent.isEmpty());
                controller.setAuthLockoutActiveRequests(true);
                controller.runAccessControlTest("", true); executor.runAll();
                assertEquals(1, fake.sent.size());
                assertNull(fake.sent.getFirst().headerValue("Authorization"));
                assertTrue(fake.errors.toString(), fake.errors.isEmpty());
            } finally { controller.shutdown(); }
        }
    }

    @Test public void jwtForgeriesAndTakeoverChecksUseRunBudgetedTransport() throws Exception {
        try (FakeMontoya fake = new FakeMontoya()) {
            ManualExecutor executor = new ManualExecutor();
            ReconController controller = ReconControllerRunLifecycleTest.controller(fake, executor);
            try {
                String token = b64("{\"alg\":\"HS256\",\"typ\":\"JWT\"}") + "." + b64("{\"sub\":\"tester\"}") + "." + b64("signature");
                var captured = fake.request(ROOT + "/account").withUpdatedHeader("Authorization", "Bearer " + token);
                fake.siteMap.add(FakeMontoya.pair(captured, FakeMontoya.response(200, "private", Map.of())));
                fake.responder = request -> FakeMontoya.response(
                        ("Bearer " + token).equals(request.headerValue("Authorization")) ? 200 : 403, "private", Map.of());
                controller.setActiveTestsEnabled(true); controller.setAuthLockoutActiveRequests(true);
                controller.setActiveRequestBudget(3);
                controller.runJwtAttacks(); executor.runAll();
                assertEquals(3, fake.sent.size());
                assertNotEquals(fake.sent.getFirst().headerValue("Authorization"), fake.sent.getLast().headerValue("Authorization"));
                fake.sent.clear();
                controller.enqueueSeeds(ROOT + "/"); // Inventory only; no background worker is started.
                controller.runSubdomainTakeoverCheck(); executor.runAll();
                assertEquals(2, fake.sent.size()); // HTTPS and HTTP, both separately admitted.
                assertTrue(fake.errors.toString(), fake.errors.isEmpty());
            } finally { controller.shutdown(); }
        }
    }

    private static String b64(String value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }
}
