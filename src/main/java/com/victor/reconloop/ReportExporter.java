package com.victor.reconloop;

import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import java.util.List;

/**
 * Exports a list of {@link AuditIssue}s to shareable formats: SARIF 2.1.0 (for code-scanning
 * dashboards / CI ingestion) and Markdown (for a bug-bounty-ready writeup). Dependency-free — the
 * JSON is emitted by hand using the existing string escaper.
 */
final class ReportExporter {

    static String toSarif(List<AuditIssue> issues) {
        StringBuilder rules = new StringBuilder();
        StringBuilder results = new StringBuilder();
        // De-duplicate rule ids while preserving first-seen order.
        java.util.LinkedHashMap<String, AuditIssue> ruleIndex = new java.util.LinkedHashMap<>();
        for (AuditIssue issue : issues) ruleIndex.putIfAbsent(ruleId(issue), issue);

        boolean firstRule = true;
        for (var entry : ruleIndex.entrySet()) {
            if (!firstRule) rules.append(",");
            firstRule = false;
            rules.append("{\"id\":\"").append(esc(entry.getKey())).append("\",")
                    .append("\"name\":\"").append(esc(entry.getValue().name())).append("\",")
                    .append("\"shortDescription\":{\"text\":\"").append(esc(entry.getValue().name())).append("\"}}");
        }

        boolean firstResult = true;
        for (AuditIssue issue : issues) {
            if (!firstResult) results.append(",");
            firstResult = false;
            results.append("{\"ruleId\":\"").append(esc(ruleId(issue))).append("\",")
                    .append("\"level\":\"").append(sarifLevel(issue.severity())).append("\",")
                    .append("\"message\":{\"text\":\"").append(esc(text(issue))).append("\"},")
                    .append("\"locations\":[{\"physicalLocation\":{\"artifactLocation\":{\"uri\":\"")
                    .append(esc(issue.baseUrl() == null ? "" : issue.baseUrl())).append("\"}}}]}");
        }

        return "{\"$schema\":\"https://json.schemastore.org/sarif-2.1.0.json\",\"version\":\"2.1.0\","
                + "\"runs\":[{\"tool\":{\"driver\":{\"name\":\"Recon Hound\",\"informationUri\":"
                + "\"https://github.com/MKlolbullen/burpaderp\",\"rules\":[" + rules + "]}},"
                + "\"results\":[" + results + "]}]}";
    }

    static String toMarkdown(List<AuditIssue> issues) {
        StringBuilder md = new StringBuilder("# Recon Hound findings\n\n");
        md.append("Total: ").append(issues.size()).append(" issue(s).\n\n");
        for (AuditIssueSeverity severity : List.of(AuditIssueSeverity.HIGH, AuditIssueSeverity.MEDIUM,
                AuditIssueSeverity.LOW, AuditIssueSeverity.INFORMATION)) {
            List<AuditIssue> bucket = issues.stream().filter(i -> i.severity() == severity).toList();
            if (bucket.isEmpty()) continue;
            md.append("## ").append(severity).append(" (").append(bucket.size()).append(")\n\n");
            for (AuditIssue issue : bucket) {
                md.append("### ").append(issue.name()).append("\n\n");
                md.append("- **URL:** ").append(issue.baseUrl() == null ? "n/a" : issue.baseUrl()).append("\n");
                md.append("- **Confidence:** ").append(issue.confidence()).append("\n\n");
                String detail = htmlToText(issue.detail());
                if (!detail.isBlank()) md.append(detail).append("\n\n");
            }
        }
        return md.toString();
    }

    private static String ruleId(AuditIssue issue) {
        String name = issue.name() == null ? "issue" : issue.name();
        return name.toLowerCase(java.util.Locale.ROOT).replaceAll("[^a-z0-9]+", "-").replaceAll("(^-|-$)", "");
    }

    private static String sarifLevel(AuditIssueSeverity severity) {
        return switch (severity) {
            case HIGH -> "error";
            case MEDIUM -> "warning";
            default -> "note";
        };
    }

    private static String text(AuditIssue issue) {
        String detail = htmlToText(issue.detail());
        String base = issue.name() + (detail.isBlank() ? "" : " — " + detail);
        return base.length() > 1000 ? base.substring(0, 997) + "..." : base;
    }

    private static String htmlToText(String html) {
        if (html == null) return "";
        return html.replaceAll("<[^>]+>", " ")
                .replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&amp;", "&")
                .replaceAll("\\s+", " ").strip();
    }

    private static String esc(String value) {
        return LlmProvider.jsonEscape(value == null ? "" : value);
    }
}
