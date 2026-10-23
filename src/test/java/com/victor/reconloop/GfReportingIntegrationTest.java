package com.victor.reconloop;

import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import org.junit.Test;
import java.util.*;
import static org.junit.Assert.*;

public class GfReportingIntegrationTest {
    private static String token() { return "amzn.mws." + "1234abcd-5678-90ab-cdef-1234567890ab"; }
    @Test public void arnAccountResourcePairsAreNotTelegramFindingsInTheCombinedNativePipeline() throws Exception {
        try (var fake = new FakeMontoya()) {
            var findings = new ReconModel.FindingTableModel();
            var controller = NativeEvidenceIntegrationTest.controller(fake, new ManualExecutor(), new ReconModel.ActiveTableModel(), findings);
            try {
                String arn = "arn:aws:sns:us-east-1:123456789012:my-application-notification-topic-prod";
                var pair = FakeMontoya.pair(fake.request("https://example.test/"), FakeMontoya.response(200, arn, Map.of()));
                var method = ReconController.class.getDeclaredMethod("scanMessage",String.class,String.class,String.class,
                        burp.api.montoya.http.message.HttpRequestResponse.class);
                method.setAccessible(true); method.invoke(controller,arn,"response",pair.request().url(),pair);
                NativeEvidenceIntegrationTest.flush();
                assertTrue(findings.snapshot().stream().noneMatch(f -> f.rule().contains("telegram")));
                assertTrue(fake.issues.stream().map(AuditIssue.class::cast).noneMatch(i -> i.name().contains("Telegram")));
                assertTrue(fake.sent.isEmpty()); assertTrue(fake.dnsLookups.isEmpty());
            } finally { controller.shutdown(); }
        }
    }
    @Test public void nativePassivePipelineUsesGfWithoutTrafficAndNeverClaimsCredentialValidity() throws Exception {
        try (var fake = new FakeMontoya()) {
            var controller = NativeEvidenceIntegrationTest.controller(fake, new ManualExecutor(),
                    new ReconModel.ActiveTableModel(), new ReconModel.FindingTableModel());
            try {
                var pair = FakeMontoya.pair(fake.request("https://example.test/"), FakeMontoya.response(200, "credential: " + token(), Map.of()));
                var issues = controller.passiveAuditIssues(pair).stream().filter(i -> i.name().contains("aws-mws-token")).toList();
                assertEquals(1, issues.size());
                assertEquals(AuditIssueConfidence.TENTATIVE, issues.getFirst().confidence());
                assertTrue(issues.getFirst().detail().contains("SIGNAL"));
                assertFalse(issues.getFirst().detail().contains(token()));
                assertTrue(controller.passiveAuditIssues(pair).stream().noneMatch(i -> i.name().contains("aws-mws-token")));
                controller.setScanGfPatterns(false);
                var second = FakeMontoya.pair(fake.request("https://example.test/other"), pair.response());
                assertTrue(controller.passiveAuditIssues(second).stream().noneMatch(i -> i.name().contains("GF ")));
                assertTrue(fake.sent.isEmpty()); assertTrue(fake.dnsLookups.isEmpty());
            } finally { controller.shutdown(); }
        }
    }
    @Test public void gfTablePersistenceIssueDetailAndReportExportsKeepMatchedSecretsRedacted() throws Exception {
        try (var fake = new FakeMontoya()) {
            var findings = new ReconModel.FindingTableModel();
            var controller = NativeEvidenceIntegrationTest.controller(fake, new ManualExecutor(), new ReconModel.ActiveTableModel(), findings);
            try {
                String body = "token=" + token();
                var pair = FakeMontoya.pair(fake.request("https://example.test/?token=" + token()), FakeMontoya.response(200,body,Map.of()));
                var method = ReconController.class.getDeclaredMethod("scanMessage",String.class,String.class,String.class,
                        burp.api.montoya.http.message.HttpRequestResponse.class);
                method.setAccessible(true); method.invoke(controller,body,"response",pair.request().url(),pair);
                NativeEvidenceIntegrationTest.flush();
                var gf = findings.snapshot().stream().filter(f -> f.rule().equals("gf:aws-mws-token")).toList();
                assertEquals(1,gf.size()); assertFalse(gf.getFirst().value().contains(token()));
                assertEquals("https://example.test/", gf.getFirst().url());
                assertTrue(fake.issues.stream().map(AuditIssue.class::cast).filter(i -> i.name().contains("GF "))
                        .noneMatch(i -> i.detail().contains(token())));
                var exported = fake.issues.stream().map(AuditIssue.class::cast).toList();
                assertFalse(ReportExporter.toSarif(exported).contains(token()));
                assertFalse(ReportExporter.toMarkdown(exported).contains(token()));
                assertTrue(fake.sent.isEmpty()); assertTrue(fake.dnsLookups.isEmpty());
            } finally { controller.shutdown(); }
            assertFalse(fake.persisted.values().toString().contains(token()));
            assertTrue(fake.errors.toString(),fake.errors.isEmpty());
        }
    }
}
