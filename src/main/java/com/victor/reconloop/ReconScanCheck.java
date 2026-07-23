package com.victor.reconloop;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.scancheck.PassiveScanCheck;

import static burp.api.montoya.scanner.AuditResult.auditResult;

/**
 * Registers Recon Hound's passive detectors with Burp's native scan pipeline. When Burp audits a
 * request/response (a passive scan of proxied traffic, or an active scan), it calls {@link #doCheck};
 * Recon Hound's engines (secrets, CORS/CSP/JWT hygiene, disclosure signals, reflected parameters)
 * then contribute findings as proper {@link AuditIssue}s that Burp owns and consolidates — so the
 * extension works whether the user drives Burp's scanner or Recon Hound's own crawl. Detection is
 * deduplicated against everything the extension has already filed (shared {@link IssueReporter}
 * dedupe), so the two paths never double-report.
 *
 * <p>Active auditing (payload injection) is deliberately not implemented here — Recon Hound's active
 * SSRF/SSTI/XSS probing stays opt-in and Collaborator-backed in its own tab.
 */
final class ReconScanCheck implements PassiveScanCheck {
    private final ReconController controller;

    ReconScanCheck(ReconController controller) {
        this.controller = controller;
    }

    @Override
    public String checkName() {
        return "Recon Hound passive checks";
    }

    @Override
    public AuditResult doCheck(HttpRequestResponse baseRequestResponse) {
        return auditResult(controller.passiveAuditIssues(baseRequestResponse));
    }

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue newIssue, AuditIssue existingIssue) {
        // Recon Hound already deduplicates its own findings, so collapse identical repeats.
        boolean same = newIssue.name().equals(existingIssue.name())
                && newIssue.baseUrl().equals(existingIssue.baseUrl())
                && newIssue.detail() != null && newIssue.detail().equals(existingIssue.detail());
        return same ? ConsolidationAction.KEEP_EXISTING : ConsolidationAction.KEEP_BOTH;
    }
}
