package com.victor.reconloop;

import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueDefinition;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import org.junit.Test;

import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;

public class ReportExporterTest {

    /** Minimal hand-implemented {@link AuditIssue}; Montoya's own {@code auditIssue(...)} factory
     *  requires a running Burp instance, but the interface itself is small enough to fake directly. */
    private record FakeIssue(String name, String detail, String remediation, String baseUrl,
                              AuditIssueSeverity severity, AuditIssueConfidence confidence) implements AuditIssue {
        @Override public HttpService httpService() { return null; }
        @Override public List<HttpRequestResponse> requestResponses() { return List.of(); }
        @Override public List<Interaction> collaboratorInteractions() { return List.of(); }
        @Override public AuditIssueDefinition definition() { return null; }
    }

    private static AuditIssue issue(String name, String detail, String url, AuditIssueSeverity severity) {
        return new FakeIssue(name, detail, "fix it", url, severity, AuditIssueConfidence.FIRM);
    }

    @Test
    public void sarifOutputIsValidJsonWithExpectedShape() {
        List<AuditIssue> issues = List.of(
                issue("Recon Hound: reflected parameter (HTML text)", "<b>evidence</b> here", "https://a.example/x", AuditIssueSeverity.HIGH),
                issue("Recon Hound: source map exposed", "plain detail", "https://a.example/y", AuditIssueSeverity.INFORMATION)
        );

        String sarif = ReportExporter.toSarif(issues);
        Map<String, Object> root = Json.asObject(Json.parse(sarif));
        assertNotNull("SARIF output must be valid JSON", root);
        assertEquals("2.1.0", root.get("version"));

        List<Object> runs = Json.asArray(root.get("runs"));
        assertEquals(1, runs.size());
        Map<String, Object> run = Json.asObject(runs.get(0));
        Map<String, Object> driver = Json.asObject(Json.asObject(run.get("tool")).get("driver"));
        assertEquals("Recon Hound", driver.get("name"));
        assertEquals(2, Json.asArray(driver.get("rules")).size());

        List<Object> results = Json.asArray(run.get("results"));
        assertEquals(2, results.size());
        Map<String, Object> firstResult = Json.asObject(results.get(0));
        assertEquals("error", firstResult.get("level"));
        assertTrue(((String) Json.asObject(firstResult.get("message")).get("text")).contains("evidence here"));

        Map<String, Object> physicalLocation = Json.asObject(
                Json.asObject(Json.asArray(firstResult.get("locations")).get(0)).get("physicalLocation"));
        assertEquals("https://a.example/x", Json.asObject(physicalLocation.get("artifactLocation")).get("uri"));
    }

    @Test
    public void sarifDedupesRuleIdsButKeepsEveryResult() {
        List<AuditIssue> issues = List.of(
                issue("Recon Hound: vulnerable dependency: jQuery 3.4.0", "d1", "https://a.example/1", AuditIssueSeverity.MEDIUM),
                issue("Recon Hound: vulnerable dependency: jQuery 3.4.0", "d2", "https://a.example/2", AuditIssueSeverity.MEDIUM)
        );

        Map<String, Object> root = Json.asObject(Json.parse(ReportExporter.toSarif(issues)));
        Map<String, Object> run = Json.asObject(Json.asArray(root.get("runs")).get(0));
        Map<String, Object> driver = Json.asObject(Json.asObject(run.get("tool")).get("driver"));

        assertEquals(1, Json.asArray(driver.get("rules")).size());
        assertEquals(2, Json.asArray(run.get("results")).size());
    }

    @Test
    public void sarifLevelMapsSeverityCorrectly() {
        assertEquals("error", levelFor(AuditIssueSeverity.HIGH));
        assertEquals("warning", levelFor(AuditIssueSeverity.MEDIUM));
        assertEquals("note", levelFor(AuditIssueSeverity.LOW));
        assertEquals("note", levelFor(AuditIssueSeverity.INFORMATION));
    }

    private static String levelFor(AuditIssueSeverity severity) {
        List<AuditIssue> issues = List.of(issue("x", "d", "https://a.example", severity));
        Map<String, Object> root = Json.asObject(Json.parse(ReportExporter.toSarif(issues)));
        Map<String, Object> run = Json.asObject(Json.asArray(root.get("runs")).get(0));
        Map<String, Object> result = Json.asObject(Json.asArray(run.get("results")).get(0));
        return (String) result.get("level");
    }

    @Test
    public void specialCharactersInIssueTextAreEscapedForValidJson() {
        List<AuditIssue> issues = List.of(
                issue("Weird \"name\" with \\backslash\\ and\nnewline",
                        "detail with \"quotes\" and \\ a backslash", "https://a.example", AuditIssueSeverity.LOW)
        );

        String sarif = ReportExporter.toSarif(issues);
        assertNotNull(Json.asObject(Json.parse(sarif)));
    }

    @Test
    public void markdownGroupsIssuesBySeverityAndOmitsEmptyBuckets() {
        List<AuditIssue> issues = List.of(
                issue("High finding", "<b>bad</b> stuff", "https://a.example/high", AuditIssueSeverity.HIGH),
                issue("Info finding", "info detail", "https://a.example/info", AuditIssueSeverity.INFORMATION)
        );

        String md = ReportExporter.toMarkdown(issues);

        assertTrue(md.startsWith("# Recon Hound findings"));
        assertTrue(md.contains("Total: 2 issue(s)"));
        assertTrue(md.contains("## HIGH (1)"));
        assertTrue(md.contains("## INFORMATION (1)"));
        assertFalse(md.contains("## MEDIUM"));
        assertFalse(md.contains("## LOW"));
        assertTrue(md.contains("### High finding"));
        assertTrue(md.contains("https://a.example/high"));
        assertTrue(md.contains("bad stuff"));
        assertFalse(md.contains("<b>"));
    }

    @Test
    public void markdownHandlesMissingBaseUrl() {
        List<AuditIssue> issues = List.of(issue("No URL", "detail", null, AuditIssueSeverity.LOW));

        String md = ReportExporter.toMarkdown(issues);

        assertTrue(md.contains("n/a"));
    }

    @Test
    public void emptyIssueListProducesEmptySarifAndZeroTotalMarkdown() {
        Map<String, Object> root = Json.asObject(Json.parse(ReportExporter.toSarif(List.of())));
        Map<String, Object> run = Json.asObject(Json.asArray(root.get("runs")).get(0));
        assertTrue(Json.asArray(run.get("results")).isEmpty());

        assertTrue(ReportExporter.toMarkdown(List.of()).contains("Total: 0 issue(s)"));
    }
}
