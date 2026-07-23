package com.victor.reconloop;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import static burp.api.montoya.scanner.audit.issues.AuditIssue.auditIssue;

/**
 * The single sink for every Recon Hound finding. Whatever the extension
 * discovers — passive signals, active/OOB probes, LLM-assisted review, or an
 * external tool such as Nuclei/SSRFMap — is registered here as a native Burp
 * {@link AuditIssue} on the site map, so it shows up in the Dashboard / Issues
 * view and is included in Burp's own reports, alongside the plugin's UI tables.
 *
 * <p>Findings are deduplicated on a caller-supplied key so the same issue is
 * never filed twice, and {@code INFORMATION}-level results are filed too (Burp
 * groups and filters them natively) to honour "results always end up there".
 */
final class IssueReporter {
    private final MontoyaApi api;
    private final Set<String> filed = ConcurrentHashMap.newKeySet();

    IssueReporter(MontoyaApi api) {
        this.api = api;
    }

    /** Maps the plugin's string severity labels onto Burp's severity enum. */
    static AuditIssueSeverity severity(String label) {
        if (label == null) return AuditIssueSeverity.INFORMATION;
        return switch (label.toUpperCase(Locale.ROOT)) {
            case "CRITICAL", "HIGH" -> AuditIssueSeverity.HIGH;
            case "MEDIUM" -> AuditIssueSeverity.MEDIUM;
            case "LOW" -> AuditIssueSeverity.LOW;
            default -> AuditIssueSeverity.INFORMATION;
        };
    }

    /** Maps a string confidence label onto Burp's confidence enum. */
    static AuditIssueConfidence confidence(String label) {
        if (label == null) return AuditIssueConfidence.TENTATIVE;
        return switch (label.toUpperCase(Locale.ROOT)) {
            case "CERTAIN" -> AuditIssueConfidence.CERTAIN;
            case "FIRM" -> AuditIssueConfidence.FIRM;
            default -> AuditIssueConfidence.TENTATIVE;
        };
    }

    /** True once a finding with this dedupe key has been filed. */
    boolean alreadyFiled(String dedupeKey) {
        return dedupeKey != null && filed.contains(dedupeKey);
    }

    /**
     * Files a finding as a native Burp audit issue, deduplicated on
     * {@code dedupeKey}. Any {@code null} evidence entries are dropped so a
     * caller can pass a possibly-null request/response without special-casing.
     *
     * @return {@code true} if newly filed, {@code false} if a matching issue
     *         was already registered or filing failed.
     */
    boolean report(String dedupeKey,
                   String title,
                   String detailHtml,
                   String remediationHtml,
                   String url,
                   AuditIssueSeverity severity,
                   AuditIssueConfidence confidence,
                   String background,
                   String remediationBackground,
                   HttpRequestResponse... evidence) {
        if (dedupeKey != null && !filed.add(dedupeKey)) return false;
        try {
            HttpRequestResponse[] cleaned = java.util.Arrays.stream(evidence == null ? new HttpRequestResponse[0] : evidence)
                    .filter(Objects::nonNull)
                    .toArray(HttpRequestResponse[]::new);
            String name = title.startsWith("Recon Hound") ? title : "Recon Hound: " + title;
            AuditIssue issue = auditIssue(
                    name, detailHtml, remediationHtml, url,
                    severity, confidence, background, remediationBackground,
                    severity, cleaned);
            api.siteMap().add(issue);
            return true;
        } catch (Exception e) {
            api.logging().logToError("Failed to file audit issue: " + title, e);
            return false;
        }
    }

    /** Convenience overload that maps a string severity label. */
    boolean report(String dedupeKey, String title, String detailHtml, String remediationHtml,
                   String url, String severityLabel, AuditIssueConfidence confidence,
                   String background, String remediationBackground, HttpRequestResponse... evidence) {
        return report(dedupeKey, title, detailHtml, remediationHtml, url,
                severity(severityLabel), confidence, background, remediationBackground, evidence);
    }
}
