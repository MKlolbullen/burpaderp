package com.victor.reconloop;

import burp.api.montoya.collaborator.*;
import burp.api.montoya.http.HttpProtocol;
import org.junit.Test;
import java.net.InetAddress;
import java.time.ZonedDateTime;
import java.util.*;
import static org.junit.Assert.*;

public class OobEvidenceTest {
    static ReconModel.ActiveRow parent(boolean dispatched) {
        var row = ActiveEvidenceCodecTest.sample(VerificationState.SIGNAL); var e = row.evidenceRecord();
        return row.withEvidence(new FindingEvidence(e.id(), e.captureId(), e.runId(), e.source(), e.detectorId(), e.detectorVersion(), e.state(),
                e.observedAt(), e.rationale(), e.reproduction(), e.originalRequest(), e.exchanges(), e.attempted(), e.omittedExchanges(),
                List.of(new FindingEvidence.OastToken("issued-token", "SSRF", "q", dispatched)), null, List.of()));
    }
    static Interaction interaction(FakeMontoya fake, String id, String custom, InteractionType type, int seconds) throws Exception {
        InteractionId identifier = FakeMontoya.proxy(InteractionId.class, (self, method, args) -> id);
        var ip = InetAddress.getByAddress(new byte[]{(byte) 203, 0, 113, 10});
        var dns = FakeMontoya.proxy(DnsDetails.class, (self, method, args) -> switch (method.getName()) {
            case "queryType" -> DnsQueryType.AAAA; case "query" -> FakeMontoya.bytes("\0\1synthetic DNS\0"); default -> null;
        });
        var rr = FakeMontoya.pair(fake.request("https://issued-token.oast.test/callback"), FakeMontoya.response(200, "ack\0", Map.of()));
        var http = FakeMontoya.proxy(HttpDetails.class, (self, method, args) -> switch (method.getName()) {
            case "protocol" -> HttpProtocol.HTTPS; case "requestResponse" -> rr; default -> null;
        });
        var smtp = FakeMontoya.proxy(SmtpDetails.class, (self, method, args) -> switch (method.getName()) {
            case "protocol" -> SmtpProtocol.SMTPS; case "conversation" -> "220 åäö\r\nEHLO synthetic\r\n"; default -> null;
        });
        return FakeMontoya.proxy(Interaction.class, (self, method, args) -> switch (method.getName()) {
            case "id" -> identifier; case "type" -> type;
            case "timeStamp" -> ZonedDateTime.parse("2026-10-21T12:00:00Z").plusSeconds(seconds);
            case "clientIp" -> ip; case "clientPort" -> 12345; case "customData" -> Optional.of(custom);
            case "dnsDetails" -> type == InteractionType.DNS ? Optional.of(dns) : Optional.empty();
            case "httpDetails" -> type == InteractionType.HTTP ? Optional.of(http) : Optional.empty();
            case "smtpDetails" -> type == InteractionType.SMTP ? Optional.of(smtp) : Optional.empty(); default -> null;
        });
    }

    @Test public void capturesExactAvailableDnsHttpAndSmtpApiObservations() throws Exception {
        try (FakeMontoya fake = new FakeMontoya()) {
            var parent = parent(true); String custom = "AC2|" + parent.evidenceRecord().captureId();
            List<ReconModel.ActiveRow> rows = new ArrayList<>();
            for (var type : InteractionType.values()) {
                var observation = OobEvidence.capture(interaction(fake, "issued-token", custom, type, 0));
                var linked = OobEvidence.link(observation, List.of(parent)); rows.add(linked);
                assertEquals(VerificationState.CONFIRMED, linked.verificationState()); assertTrue(linked.evidenceRecord().complete());
                assertEquals(parent.url(), linked.url()); assertEquals(parent.evidenceRecord().runId(), linked.evidenceRecord().runId());
                assertEquals(List.of(parent.evidenceRecord().id()), linked.evidenceRecord().relatedEvidenceIds());
                if (type == InteractionType.DNS) {
                    assertEquals("AAAA", observation.dnsQueryType());
                    assertArrayEquals(FakeMontoya.bytes("\0\1synthetic DNS\0").getBytes(), observation.dnsQuery().decoded());
                } else if (type == InteractionType.HTTP) {
                    assertEquals("HTTPS", observation.httpProtocol());
                    assertArrayEquals(fake.request("https://issued-token.oast.test/callback").toByteArray().getBytes(), observation.httpRequest().decoded());
                    assertArrayEquals(FakeMontoya.response(200, "ack\0", Map.of()).toByteArray().getBytes(), observation.httpResponse().decoded());
                } else {
                    assertEquals("SMTPS", observation.smtpProtocol());
                    assertEquals("220 åäö\r\nEHLO synthetic\r\n", new String(observation.smtpUtf8().decoded(), java.nio.charset.StandardCharsets.UTF_8));
                }
                assertTrue(linked.evidence().contains("not browser execution"));
            }
            assertEquals(rows, ActiveEvidenceCodec.decode(ActiveEvidenceCodec.encode(rows)).rows());
            assertTrue(fake.sent.isEmpty()); assertTrue(fake.dnsLookups.isEmpty());
        }
    }

    @Test public void noDispatchWrongTokenWrongCaptureAndLegacyMetadataRemainUnlinked() throws Exception {
        try (FakeMontoya fake = new FakeMontoya()) {
            var parent = parent(true); String custom = "AC2|" + parent.evidenceRecord().captureId();
            for (var event : List.of(OobEvidence.capture(interaction(fake, "wrong-token", custom, InteractionType.DNS, 0)),
                    OobEvidence.capture(interaction(fake, "issued-token", "AC2|" + UUID.randomUUID(), InteractionType.DNS, 0)),
                    OobEvidence.capture(interaction(fake, "issued-token", "AC|SSRF|q|" + parent.url(), InteractionType.DNS, 0)))) {
                var row = OobEvidence.link(event, List.of(parent));
                assertEquals(VerificationState.CANDIDATE, row.verificationState()); assertEquals("", row.url());
                assertEquals("", row.evidenceRecord().runId()); assertTrue(row.evidenceRecord().relatedEvidenceIds().isEmpty());
            }
            var notDispatched = parent(false);
            var event = OobEvidence.capture(interaction(fake, "issued-token", "AC2|" + notDispatched.evidenceRecord().captureId(), InteractionType.DNS, 0));
            assertEquals(VerificationState.CANDIDATE, OobEvidence.link(event, List.of(notDispatched)).verificationState());
        }
    }

    @Test public void stableFingerprintUpgradesUnlinkedRowAndKeepsDistinctCallbacks() throws Exception {
        try (FakeMontoya fake = new FakeMontoya()) {
            var parent = parent(true); String custom = "AC2|" + parent.evidenceRecord().captureId();
            var event = OobEvidence.capture(interaction(fake, "issued-token", custom, InteractionType.HTTP, 0));
            var duplicate = OobEvidence.capture(interaction(fake, "issued-token", custom, InteractionType.HTTP, 0));
            var later = OobEvidence.capture(interaction(fake, "issued-token", custom, InteractionType.HTTP, 1));
            assertEquals(event.fingerprint(), duplicate.fingerprint()); assertNotEquals(event.fingerprint(), later.fingerprint());
            var table = new ReconModel.ActiveTableModel(); table.add(OobEvidence.link(event, List.of())); table.add(parent);
            table.add(OobEvidence.link(duplicate, table.snapshot()));
            assertEquals(2, table.getRowCount());
            assertEquals(VerificationState.CONFIRMED, table.row(0).verificationState());
            table.add(OobEvidence.link(later, table.snapshot())); assertEquals(3, table.getRowCount());
        }
    }

    @Test public void sharedVariantAssociationsDoNotDuplicatePacketsOrClaimUniqueProvenance() throws Exception {
        try (FakeMontoya fake = new FakeMontoya()) {
            var parent = parent(true); var e = parent.evidenceRecord();
            var second = parent.withEvidence(new FindingEvidence(UUID.randomUUID().toString(), e.captureId(), e.runId(), "CORPUS", e.detectorId(), e.detectorVersion(),
                    e.state(), e.observedAt(), e.rationale(), e.reproduction(), e.originalRequest(), e.exchanges(), e.attempted(), e.omittedExchanges(), e.issuedTokens(), null, List.of()));
            var event = OobEvidence.capture(interaction(fake, "issued-token", "AC2|" + e.captureId(), InteractionType.DNS, 0));
            var linked = OobEvidence.link(event, List.of(parent, second));
            assertEquals(2, linked.evidenceRecord().relatedEvidenceIds().size());
            assertEquals(1, linked.evidenceRecord().attempted()); assertEquals(1, linked.evidenceRecord().exchanges().size());
            assertTrue(linked.evidence().contains("ambiguous"));
            var other = second.withEvidence(new FindingEvidence(second.evidenceRecord().id(), e.captureId(), UUID.randomUUID().toString(), "CORPUS", e.detectorId(), e.detectorVersion(),
                    e.state(), e.observedAt(), e.rationale(), e.reproduction(), e.originalRequest(), List.of(), 0, 0, e.issuedTokens(), null, List.of()));
            assertEquals(VerificationState.CANDIDATE, OobEvidence.link(event, List.of(parent, other)).verificationState());
        }
    }

    @Test public void controllerCanAssociateLateParentThenPersistAndSuppressRefilingAfterRestore() throws Exception {
        try (FakeMontoya fake = new FakeMontoya()) {
            var parent = parent(true); var active = new ReconModel.ActiveTableModel();
            var interaction = interaction(fake, "issued-token", "AC2|" + parent.evidenceRecord().captureId(), InteractionType.DNS, 0);
            var client = FakeMontoya.proxy(CollaboratorClient.class, (self, method, args) -> List.of(interaction));
            var controller = NativeEvidenceIntegrationTest.controller(fake, new ManualExecutor(), active, new ReconModel.FindingTableModel());
            var field = ReconController.class.getDeclaredField("collaborator"); field.setAccessible(true); field.set(controller, client);
            var poll = ReconController.class.getDeclaredMethod("pollCollaborator"); poll.setAccessible(true);
            poll.invoke(controller); NativeEvidenceIntegrationTest.flush();
            assertEquals(VerificationState.CANDIDATE, active.row(0).verificationState()); assertTrue(fake.issues.isEmpty());
            javax.swing.SwingUtilities.invokeAndWait(() -> active.add(parent));
            poll.invoke(controller); NativeEvidenceIntegrationTest.flush();
            assertEquals(2, active.getRowCount()); assertEquals(1, fake.issues.size());
            poll.invoke(controller); NativeEvidenceIntegrationTest.flush(); assertEquals(1, fake.issues.size());
            controller.shutdown();
            var restored = new ReconModel.ActiveTableModel(); var next = NativeEvidenceIntegrationTest.controller(fake, new ManualExecutor(), restored, new ReconModel.FindingTableModel());
            try {
                NativeEvidenceIntegrationTest.flush(); field.set(next, client); poll.invoke(next); NativeEvidenceIntegrationTest.flush();
                assertEquals(2, restored.getRowCount()); assertEquals(1, fake.issues.size()); assertTrue(fake.sent.isEmpty());
                assertTrue(fake.errors.toString(), fake.errors.isEmpty());
            } finally { next.shutdown(); }
        }
    }
}
