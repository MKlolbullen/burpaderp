package com.victor.reconloop;

import org.junit.Test;
import java.net.URI;
import java.util.Map;
import static org.junit.Assert.*;

public class RedirectPolicyIntegrationTest {
    @Test public void everyHopIsCountedAndOutOfScopeHopIsNeverSent() {
        try (FakeMontoya fake = new FakeMontoya()) {
            ReconController controller = ReconControllerRunLifecycleTest.controller(fake, new ManualExecutor());
            try {
                fake.inScope = url -> URI.create(url).getHost().equals("api.example.test");
                fake.responder = request -> FakeMontoya.response(302, "", Map.of("Location",
                        URI.create(request.url()).getPath().equals("/start") ? "/second" : "https://outside.test/third"));
                controller.crawlOne(ReconControllerRunLifecycleTest.item("/start"));
                assertEquals(2, fake.sent.size());
                assertEquals(2, controller.currentCrawlRun().requestBudget().used());
                assertTrue(fake.sent.stream().allMatch(r -> fake.inScope.test(r.url())));
            } finally { controller.shutdown(); }
        }
    }

    @Test public void protectedHopAndRedirectLoopsStopAtTheGate() {
        for (String location : new String[]{"http://169.254.169.254/latest/meta-data", "/start"}) {
            try (FakeMontoya fake = new FakeMontoya()) {
                ReconController controller = ReconControllerRunLifecycleTest.controller(fake, new ManualExecutor());
                try {
                    fake.responder = request -> FakeMontoya.response(302, "", Map.of("Location", location));
                    controller.crawlOne(ReconControllerRunLifecycleTest.item("/start"));
                    assertEquals(location, 1, fake.sent.size());
                } finally { controller.shutdown(); }
            }
        }
    }

    @Test public void crtShExceptionCannotBecomeTargetTrafficThroughRedirects() {
        try (FakeMontoya fake = new FakeMontoya()) {
            fake.responder = request -> FakeMontoya.response(302, "", Map.of("Location", "https://target.test/"));
            CertificateTransparencyClient client = new CertificateTransparencyClient(fake.api);
            client.enumerate("target.test");
            client.enumerate("target.test@outside.test");
            assertEquals(1, fake.sent.size());
            assertEquals("crt.sh", URI.create(fake.sent.getFirst().url()).getHost());
            assertEquals("https", URI.create(fake.sent.getFirst().url()).getScheme());
            assertEquals("GET", fake.sent.getFirst().method());
            assertEquals(1, fake.redirectModes.size()); // fake rejects any mode other than NEVER
        }
    }
}
