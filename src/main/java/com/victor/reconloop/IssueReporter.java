package com.victor.reconloop;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Marker;
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

    /** Snapshot of the dedupe keys filed so far (for persistence across sessions). */
    Set<String> filedSnapshot() {
        return new java.util.HashSet<>(filed);
    }

    /** Re-seeds the dedupe set from persisted keys so a reloaded session won't re-file old findings. */
    void restore(java.util.Collection<String> keys) {
        if (keys != null) filed.addAll(keys);
    }

    /** Clears the dedupe set (used on Reset so findings can be re-filed after the site map is cleared). */
    void clearFiled() {
        filed.clear();
    }

    /**
     * Returns {@code rr} with a response marker highlighting bytes {@code [start, end)}, or unchanged
     * when the bounds are invalid / there is no response. Bounds are clamped to the message length so
     * an out-of-range offset can never produce an invalid marker at runtime.
     */
    static HttpRequestResponse withResponseEvidence(HttpRequestResponse rr, int start, int end) {
        if (rr == null || !rr.hasResponse() || start < 0 || end <= start) return rr;
        try {
            int len = rr.response().toString().length();
            int e = Math.min(end, len);
            if (start >= len || e <= start) return rr;
            return rr.withResponseMarkers(Marker.marker(start, e));
        } catch (Exception ex) {
            return rr;
        }
    }

    /** Request-side twin of {@link #withResponseEvidence}. */
    static HttpRequestResponse withRequestEvidence(HttpRequestResponse rr, int start, int end) {
        if (rr == null || rr.request() == null || start < 0 || end <= start) return rr;
        try {
            int len = rr.request().toString().length();
            int e = Math.min(end, len);
            if (start >= len || e <= start) return rr;
            return rr.withRequestMarkers(Marker.marker(start, e));
        } catch (Exception ex) {
            return rr;
        }
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
        AuditIssue issue = buildIfNew(dedupeKey, title, detailHtml, remediationHtml, url,
                severity, confidence, background, remediationBackground, evidence);
        if (issue == null) return false;
        api.siteMap().add(issue);
        return true;
    }

    /**
     * Builds a deduplicated audit issue but does NOT add it to the site map — for use inside a
     * {@code ScanCheck.passiveAudit}, where Burp's scanner owns issue registration and consolidation.
     * Returns {@code null} if a matching issue was already filed/built or construction failed.
     */
    AuditIssue buildIfNew(String dedupeKey,
                          String title,
                          String detailHtml,
                          String remediationHtml,
                          String url,
                          AuditIssueSeverity severity,
                          AuditIssueConfidence confidence,
                          String background,
                          String remediationBackground,
                          HttpRequestResponse... evidence) {
        // Normalise CR/LF so keys survive the newline-delimited persisted store (PersistedState).
        if (dedupeKey != null) dedupeKey = dedupeKey.replace('\n', ' ').replace('\r', ' ');
        if (dedupeKey != null && !filed.add(dedupeKey)) return null;
        try {
            HttpRequestResponse[] cleaned = java.util.Arrays.stream(evidence == null ? new HttpRequestResponse[0] : evidence)
                    .filter(Objects::nonNull)
                    .toArray(HttpRequestResponse[]::new);
            String name = title.startsWith("Recon Hound") ? title : "Recon Hound: " + title;
            return auditIssue(
                    name, detailHtml, remediationHtml, url,
                    severity, confidence, background, remediationBackground,
                    severity, cleaned);
        } catch (Exception e) {
            api.logging().logToError("Failed to build audit issue: " + title, e);
            return null;
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
