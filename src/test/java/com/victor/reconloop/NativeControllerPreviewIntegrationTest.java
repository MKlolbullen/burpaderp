package com.victor.reconloop;

import burp.api.montoya.http.message.requests.HttpRequest;
import org.junit.Test;
import java.nio.charset.StandardCharsets;
import java.util.*;
import static com.victor.reconloop.NativeProbePreviewIntegrationTest.*;
import static org.junit.Assert.*;

public class NativeControllerPreviewIntegrationTest {
    private static final String ROOT = "https://api.example.test";

    @Test public void everyNativePreviewIsReadOnlyWithSendingDisabledEvenWhenOastIsGranted() throws Exception {
        try (FakeMontoya fake = new FakeMontoya()) {
            ManualExecutor executor = new ManualExecutor();
            ReconController controller = ReconControllerRunLifecycleTest.controller(fake,executor);
            try {
                controller.enqueueSeeds(ROOT + "/queued");
                controller.setOastActiveRequests(true); controller.setMutatingActiveRequests(true);
                controller.setPersistentPayloadActiveRequests(true);
                controller.setTimeDelayActiveRequests(true); controller.setUploadActiveRequests(true); controller.setAuthLockoutActiveRequests(true);
                var captured = fake.request(ROOT + "/PATH_SECRET?q=QUERY_SECRET").withHeader("Authorization","Bearer " + token())
                        .withHeader("Cookie","COOKIE_SECRET").withBody("BODY_SECRET");
                fake.siteMap.add(FakeMontoya.pair(captured,FakeMontoya.response(200,"private",Map.of())));
                String before = controller.status();
                List<String> scopeBefore = List.copyOf(fake.scopeChanges);
                fake.apiAccesses.clear();
                List<String> previews = List.of(controller.previewActiveTests(null), controller.previewActiveTests("blind-xss"),
                        controller.previewCorpusFuzz(Set.of(PayloadEncoder.Encoding.RAW),1),controller.previewJwtAttacks(),
                        controller.previewTakeover(),controller.previewAccessControl("Authorization: ALT_SECRET",false),
                        controller.previewCrawl(ROOT + "/NEW_PATH_SECRET?key=NEW_QUERY_SECRET"));
                for (String preview : previews) {
                    assertTrue(preview,preview.contains("Dry run"));
                    for (String secret : List.of("PATH_SECRET","QUERY_SECRET","COOKIE_SECRET","BODY_SECRET","ALT_SECRET",token())) assertFalse(preview,preview.contains(secret));
                }
                assertTrue(previews.get(1).contains("PENDING_BINDING"));
                assertFalse(previews.get(1).contains("MISSING_PERMISSION"));
                assertEquals(before,controller.status()); assertEquals(scopeBefore,fake.scopeChanges);
                assertFalse(fake.apiAccesses.contains("http")); assertFalse(fake.apiAccesses.contains("collaborator"));
                assertEquals(1,fake.siteMap.size()); assertNull(controller.currentCrawlRun());
                executor.runAll(); assertTrue(fake.sent.isEmpty()); assertTrue(fake.errors.toString(),fake.errors.isEmpty());
            } finally { controller.shutdown(); }
        }
    }

    @Test public void jwtPlansPreserveCapturedDataAndMatchBaselineNoneAndWeakSecretDispatches() throws Exception {
        try (FakeMontoya fake = new FakeMontoya()) {
            ManualExecutor executor = new ManualExecutor();
            ReconController controller = ReconControllerRunLifecycleTest.controller(fake,executor);
            try {
                String token = token();
                var captured = fake.request(ROOT + "/PATH_SECRET?q=QUERY_SECRET").withHeader("Authorization","Bearer " + token)
                        .withHeader("Cookie","COOKIE_SECRET").withBody("BODY_SECRET");
                var weak = JwtRequestPlanner.weakSecret(captured,token);
                assertNotNull(weak); assertEquals("password",weak.secret());
                List<NativeRequestStep> expected = materialize(JwtRequestPlanner.plan(captured,token));
                assertEquals(6,expected.size());
                assertTrue(expected.stream().allMatch(step -> step.request().bodyToString().equals("BODY_SECRET")));
                fake.siteMap.add(FakeMontoya.pair(captured,FakeMontoya.response(200,"private",Map.of())));
                controller.setAuthLockoutActiveRequests(true);
                String preview = controller.previewJwtAttacks();
                assertFalse(preview.contains(token)); assertFalse(preview.contains("password")); assertFalse(preview.contains("BODY_SECRET"));
                assertTrue(fake.sent.isEmpty());
                controller.setActiveTestsEnabled(true); controller.runJwtAttacks(); executor.runAll();
                assertEquals(expected.size(),fake.sent.size());
                for (int i = 0; i < expected.size(); i++) assertTrue(expected.get(i).plan().matches(fake.sent.get(i).withService(expected.get(i).request().httpService())));
                assertTrue(fake.errors.toString(),fake.errors.isEmpty());
            } finally { controller.shutdown(); }
        }
    }

    @Test public void accessControlPreviewAndExecutionShareSafeTargetSelectionAndIdentityMutation() throws Exception {
        try (FakeMontoya fake = new FakeMontoya()) {
            ManualExecutor executor = new ManualExecutor();
            ReconController controller = ReconControllerRunLifecycleTest.controller(fake,executor);
            try {
                var safe = fake.request(ROOT + "/account").withHeader("Authorization","PRIVILEGED_SECRET").withHeader("Cookie","COOKIE_SECRET");
                fake.siteMap.add(FakeMontoya.pair(safe,FakeMontoya.response(200,"private",Map.of())));
                fake.siteMap.add(FakeMontoya.pair(safe,FakeMontoya.response(200,"duplicate",Map.of())));
                fake.siteMap.add(FakeMontoya.pair(safe.withMethod("POST"),FakeMontoya.response(200,"mutating",Map.of())));
                String headers = "Authorization: ALT_SECRET\nX-Tenant: TENANT_SECRET";
                controller.setAuthLockoutActiveRequests(true); controller.setMutatingActiveRequests(true);
                String preview = controller.previewAccessControl(headers,false);
                assertTrue(preview,preview.contains("up to 1"));
                for (String secret : List.of("PRIVILEGED_SECRET","COOKIE_SECRET","ALT_SECRET","TENANT_SECRET")) assertFalse(preview.contains(secret));
                NativeRequestStep expected = new AccessControlEngine(headers,false).plan(safe);
                assertNull(expected.request().headerValue("Cookie")); assertEquals("ALT_SECRET",expected.request().headerValue("Authorization"));
                controller.setActiveTestsEnabled(true); controller.runAccessControlTest(headers,false); executor.runAll();
                assertEquals(1,fake.sent.size()); assertTrue(expected.plan().matches(fake.sent.getFirst().withService(expected.request().httpService())));
            } finally { controller.shutdown(); }
        }
    }

    @Test public void takeoverPreviewIncludesHttpFallbackWithoutAssumingAnHttpsFingerprint() throws Exception {
        try (FakeMontoya fake = new FakeMontoya()) {
            ManualExecutor executor = new ManualExecutor();
            ReconController controller = ReconControllerRunLifecycleTest.controller(fake,executor);
            try {
                controller.enqueueSeeds(ROOT + "/");
                var expected = materialize(TakeoverRequestPlanner.plan("api.example.test"));
                assertEquals(2,expected.size()); assertEquals(NativeRequestStep.Condition.FALLBACK,expected.getLast().condition());
                String preview = controller.previewTakeover();
                assertTrue(preview.contains("HTTP fallback")); assertTrue(preview.contains("not a worst-case bound")); assertTrue(fake.sent.isEmpty());
                fake.responder = request -> FakeMontoya.response(200,"There isn't a GitHub Pages site here.",Map.of());
                controller.setActiveTestsEnabled(true); controller.runSubdomainTakeoverCheck(); executor.runAll();
                assertEquals(1,fake.sent.size()); assertTrue(expected.getFirst().plan().matches(fake.sent.getFirst().withService(expected.getFirst().request().httpService())));
            } finally { controller.shutdown(); }
        }
    }

    @Test public void crawlPreviewDoesNotInventRedirectUrlsOrSpendAnExistingCrawlLedger() {
        try (FakeMontoya fake = new FakeMontoya()) {
            ReconController controller = ReconControllerRunLifecycleTest.controller(fake,new ManualExecutor());
            try {
                controller.setMaxRequests(3); controller.setMaxRedirects(2);
                String seed = ROOT + "/start?key=QUERY_SECRET";
                String before = controller.status();
                String preview = controller.previewCrawl(seed);
                assertTrue(preview,preview.contains("PENDING_DESTINATION")); assertTrue(preview.contains("2 runtime templates"));
                assertFalse(preview.contains("QUERY_SECRET")); assertEquals(before,controller.status()); assertNull(controller.currentCrawlRun());
                fake.responder = request -> request.url().contains("/start") ? FakeMontoya.response(302,"",Map.of("Location","/next")) : FakeMontoya.response(200,"",Map.of());
                controller.crawlOne(ReconControllerRunLifecycleTest.item("/start?key=QUERY_SECRET"));
                assertEquals(2,fake.sent.size()); ScanRun run = controller.currentCrawlRun();
                assertEquals(2,run.requestBudget().used());
                String nextPreview = controller.previewCrawl(seed);
                assertTrue(nextPreview.contains("scenario: 1")); assertEquals(2,run.requestBudget().used()); assertEquals(2,fake.sent.size());
                controller.setFollowRedirects(false);
                assertFalse(controller.previewCrawl(seed).contains("PENDING_DESTINATION"));
            } finally { controller.shutdown(); }
        }
    }

    @Test public void invalidPreviewInputNeverExpandsScopeOrLogsCapturedSecrets() {
        try (FakeMontoya fake = new FakeMontoya()) {
            ReconController controller = ReconControllerRunLifecycleTest.controller(fake,new ManualExecutor());
            try {
                assertTrue(controller.previewCrawl("not a URI SECRET_VALUE").contains("No requests sent"));
                assertTrue(controller.previewAccessControl("",false).contains("No requests sent"));
                assertTrue(controller.previewCorpusFuzz(Set.of(),1).contains("No requests sent"));
                assertTrue(fake.errors.isEmpty()); assertTrue(fake.sent.isEmpty()); assertTrue(fake.scopeChanges.isEmpty());
            } finally { controller.shutdown(); }
        }
    }

    @Test public void crawlPreviewKeepsQueuedWorkBeforeNewSeedsAndIgnoresCommentLines() {
        try (FakeMontoya fake = new FakeMontoya()) {
            ReconController controller = ReconControllerRunLifecycleTest.controller(fake,new ManualExecutor());
            try {
                controller.setMaxRequests(1); controller.setFollowRedirects(false);
                controller.enqueueSeeds("https://queued.example.test/");
                String before = controller.status();
                String preview = controller.previewCrawl("# comment\nhttps://new.example.test/\n");
                assertTrue(preview,preview.contains("Dry run"));
                assertTrue(preview.indexOf("queued.example.test") < preview.indexOf("new.example.test"));
                assertTrue(preview.contains("BUDGET_EXHAUSTED")); assertTrue(preview.contains("global remaining: 1"));
                assertEquals(before,controller.status()); assertNull(controller.currentCrawlRun()); assertTrue(fake.sent.isEmpty());
            } finally { controller.shutdown(); }
        }
    }

    @Test public void crawlerCountRemainsAScenarioWhenRedirectsAreDisabled() {
        try (FakeMontoya fake = new FakeMontoya()) {
            ReconController controller = ReconControllerRunLifecycleTest.controller(fake,new ManualExecutor());
            try {
                controller.setFollowRedirects(false);
                String preview = controller.previewCrawl(ROOT + "/seed");
                assertTrue(preview,preview.contains("not a worst-case bound"));
                assertTrue(preview.contains("Future crawl discoveries are not included"));
                assertFalse(preview.contains("Admissible requests: up to"));
                assertTrue(fake.sent.isEmpty());
            } finally { controller.shutdown(); }
        }
    }

    private static String token() {
        String unsigned = b64("{\"alg\":\"HS256\",\"typ\":\"JWT\"}") + "." + b64("{\"sub\":\"CLAIM_SECRET\"}") + ".signature";
        return JwtAttackEngine.forgeWithSecret(unsigned,"password","hs256");
    }
    private static String b64(String text) { return Base64.getUrlEncoder().withoutPadding().encodeToString(text.getBytes(StandardCharsets.UTF_8)); }
}
