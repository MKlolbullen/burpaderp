package com.victor.reconloop;

import burp.api.montoya.collaborator.CollaboratorPayload;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.function.Supplier;

/** One probe/insertion point or corpus variant. Never infers a mutation from detector prose. */
final class EvidenceCapture {
    final String captureId;
    private final String runId, source, probeId, targetUrl;
    private final FindingEvidence.Bytes original;
    private final List<FindingEvidence.Exchange> exchanges = new ArrayList<>();
    private final List<HttpRequestResponse> messages = new ArrayList<>();
    private final List<FindingEvidence.OastToken> tokens = new ArrayList<>();
    private int attempted, retained;

    EvidenceCapture(ScanRun run, HttpRequest base, String source, String probeId) {
        this(run == null ? "" : run.id().toString(), base, source, probeId, UUID.randomUUID().toString());
    }
    private EvidenceCapture(String runId, HttpRequest base, String source, String probeId, String captureId) {
        this.runId = runId; this.source = source; this.probeId = probeId; this.captureId = captureId;
        targetUrl = base.url();
        original = bytes(() -> base.toByteArray().getBytes()); retained = original.retainedBytes();
    }
    EvidenceCapture variant(HttpRequest base) {
        EvidenceCapture next = new EvidenceCapture(runId, base, source, probeId, captureId); next.tokens.addAll(tokens); return next;
    }
    String correlation() { return "AC2|" + captureId; }
    void issued(CollaboratorPayload payload, String testClass, String parameter) {
        if (payload == null) return;
        try {
            String id = payload.id() == null ? "" : payload.id().toString();
            if (!id.isEmpty()) tokens.add(new FindingEvidence.OastToken(id, testClass, parameter, false));
        } catch (RuntimeException unavailable) { /* Sending is independent of optional correlation metadata. */ }
    }
    void record(ActiveRequestGateway.Result result) { record(result, false); }
    void record(ActiveRequestGateway.Result result, boolean oastPayload) {
        attempted++;
        if (oastPayload && result != null && result.dispatched())
            tokens.replaceAll(t -> new FindingEvidence.OastToken(t.payloadId(), t.testClass(), t.parameter(), true));
        if (result == null || result.exchange() == null) return;
        if (exchanges.size() >= FindingEvidence.MAX_EXCHANGES) return;
        FindingEvidence.Exchange exchange = result.exchange();
        if (retained + exchange.retainedBytes() > FindingEvidence.MAX_CASE_BYTES) exchange = exchange.withoutBytes();
        retained += exchange.retainedBytes(); exchanges.add(exchange);
        if (result.dispatched() && result.response() != null) messages.add(result.response());
    }
    FindingEvidence snapshot(VerificationState state, String rationale) {
        return new FindingEvidence(UUID.randomUUID().toString(), captureId, runId, source, probeId,
                FindingEvidence.DETECTOR_VERSION, state, Instant.now().toString(), rationale,
                "Inspect the captured original and ordered request/response observations. Reproduce only with current scope and risk grants; refresh session credentials and OAST identifiers. Stored data never authorizes replay.",
                original, exchanges, attempted, Math.max(0, attempted - exchanges.size()), tokens, null, List.of());
    }
    void attach(List<ActiveTestEngine.ActiveFinding> findings, int from) {
        if (findings.size() == from && tokens.stream().anyMatch(FindingEvidence.OastToken::dispatchAttempted)) {
            var token = tokens.stream().filter(FindingEvidence.OastToken::dispatchAttempted).findFirst().orElseThrow();
            findings.add(new ActiveTestEngine.ActiveFinding("INFO", token.testClass(), token.parameter(),
                    "OAST dispatch attempted; awaiting a correlated interaction (delivery not established by the dispatch).",
                    VerificationState.SIGNAL, targetUrl));
        }
        for (int i = from; i < findings.size(); i++) {
            var finding = findings.get(i);
            findings.set(i, finding.withEvidence(snapshot(finding.verificationState(), finding.evidence()), messages));
        }
    }
    void recordWithTokens(ActiveRequestGateway.Result result, HttpRequest request) {
        boolean contains = false;
        try {
            String raw = new String(request.toByteArray().getBytes(), java.nio.charset.StandardCharsets.ISO_8859_1);
            contains = tokens.stream().anyMatch(t -> raw.contains(t.payloadId()));
        } catch (RuntimeException unavailable) { /* no correlation claim without inspecting the mutation */ }
        record(result, contains);
    }

    static FindingEvidence helper(String detectorId, VerificationState state, String rationale, HttpRequest original,
                                  ActiveRequestGateway.Result... results) {
        String runId = java.util.Arrays.stream(results).filter(java.util.Objects::nonNull).map(ActiveRequestGateway.Result::exchange)
                .filter(java.util.Objects::nonNull).map(FindingEvidence.Exchange::runId).findFirst().orElse("");
        EvidenceCapture capture = new EvidenceCapture(runId, original, "NATIVE_HELPER", detectorId, UUID.randomUUID().toString());
        for (var result : results) if (result != null) capture.record(result);
        return capture.snapshot(state, rationale);
    }

    static FindingEvidence.Bytes bytes(Supplier<byte[]> read) {
        try { return FindingEvidence.Bytes.capture(read.get()); }
        catch (RuntimeException e) { return FindingEvidence.Bytes.unavailable(); }
    }
    static FindingEvidence.Exchange exchange(ScanRun run, RequestPlan plan, HttpRequest request,
                                             ActiveRequestGateway.Result result, long elapsed) {
        var metadata = plan.policyRequest();
        HttpRequestResponse pair = result.response();
        return new FindingEvidence.Exchange(UUID.randomUUID().toString(), run.id().toString(), metadata.probeId(),
                metadata.method(), metadata.url(), result.decision().code().name(), result.dispatched(), Math.max(0, elapsed),
                result.error() == null ? "" : result.error().getClass().getSimpleName(), bytes(() -> request.toByteArray().getBytes()),
                bytes(() -> pair.request().toByteArray().getBytes()), bytes(() -> pair.response().toByteArray().getBytes()));
    }
}
