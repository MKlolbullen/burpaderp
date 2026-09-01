package com.victor.reconloop;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Marker;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import com.victor.reconloop.contracts.VerificationState;
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
 * Raw dedupe keys are never retained: they are normalised and SHA-256 fingerprinted before entering
 * memory or project persistence, because callers may include discovered credentials in those keys.
 */
final class IssueReporter {
    private static final String KEY_PREFIX = "sha256:";

    private final MontoyaApi api;
    private final Set<String> filed = ConcurrentHashMap.newKeySet();
    private volatile UUID runId = UUID.randomUUID();
    private volatile VerificationState defaultState = VerificationState.SIGNAL;

    IssueReporter(MontoyaApi api) {
        this.api = api;
    }

    void setRunId(UUID runId) {
        if (runId != null) this.runId = runId;
    }

    UUID runId() { return runId; }

    void setDefaultState(VerificationState state) {
        if (state != null) this.defaultState = state;
    }

    static AuditIssueSeverity severity(String label) {
        if (label == null) return AuditIssueSeverity.INFORMATION;
        return switch (label.toUpperCase(Locale.ROOT)) {
            case "CRITICAL", "HIGH" -> AuditIssueSeverity.HIGH;
            case "MEDIUM" -> AuditIssueSeverity.MEDIUM;
            case "LOW" -> AuditIssueSeverity.LOW;
            default -> AuditIssueSeverity.INFORMATION;
        };
    }

    static AuditIssueConfidence confidence(String label) {
        if (label == null) return AuditIssueConfidence.TENTATIVE;
        return switch (label.toUpperCase(Locale.ROOT)) {
            case "CERTAIN" -> AuditIssueConfidence.CERTAIN;
            case "FIRM" -> AuditIssueConfidence.FIRM;
            default -> AuditIssueConfidence.TENTATIVE;
        };
    }

    static String fingerprintKey(String dedupeKey) {
        if (dedupeKey == null) return null;
        String normalized = dedupeKey.replace('\n', ' ').replace('\r', ' ');
        if (normalized.startsWith(KEY_PREFIX)
                && normalized.length() == KEY_PREFIX.length() + 64
                && normalized.substring(KEY_PREFIX.length()).matches("[0-9a-f]{64}")) {
            return normalized;
        }
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(normalized.getBytes(StandardCharsets.UTF_8));
            return KEY_PREFIX + HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is unavailable", e);
        }
    }

    boolean alreadyFiled(String dedupeKey) {
        String fingerprint = fingerprintKey(dedupeKey);
        return fingerprint != null && filed.contains(fingerprint);
    }

    Set<String> filedSnapshot() {
        return new java.util.HashSet<>(filed);
    }

    void restore(java.util.Collection<String> keys) {
        if (keys == null) return;
        for (String key : keys) {
            String fingerprint = fingerprintKey(key);
            if (fingerprint != null) filed.add(fingerprint);
        }
    }

    void clearFiled() {
        filed.clear();
    }

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
        String fingerprint = fingerprintKey(dedupeKey);
        if (fingerprint != null && !filed.add(fingerprint)) return null;
        try {
            HttpRequestResponse[] cleaned = java.util.Arrays.stream(evidence == null ? new HttpRequestResponse[0] : evidence)
                    .filter(Objects::nonNull)
                    .toArray(HttpRequestResponse[]::new);
            String name = title.startsWith("Recon Hound") ? title : "Recon Hound: " + title;
            String annotated = annotate(detailHtml);
            return auditIssue(
                    name, annotated, remediationHtml, url,
                    severity, confidence, background, remediationBackground,
                    severity, cleaned);
        } catch (Exception e) {
            if (fingerprint != null) filed.remove(fingerprint);
            api.logging().logToError("Failed to build audit issue: " + title, e);
            return null;
        }
    }

    boolean report(String dedupeKey, String title, String detailHtml, String remediationHtml,
                   String url, String severityLabel, AuditIssueConfidence confidence,
                   String background, String remediationBackground, HttpRequestResponse... evidence) {
        return report(dedupeKey, title, detailHtml, remediationHtml, url,
                severity(severityLabel), confidence, background, remediationBackground, evidence);
    }

    private String annotate(String detailHtml) {
        String body = detailHtml == null ? "" : detailHtml;
        return "<p><b>Run</b> " + runId + " &nbsp; <b>Verification</b> " + defaultState + "</p>" + body;
    }
}
