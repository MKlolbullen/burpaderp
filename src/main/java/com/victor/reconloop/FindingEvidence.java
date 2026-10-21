package com.victor.reconloop;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;

/** Versioned observations, not replay authorization. Payload bytes stay inside the Burp project. */
record FindingEvidence(String id, String captureId, String runId, String source, String detectorId,
                       String detectorVersion, VerificationState state, String observedAt,
                       String rationale, String reproduction, Bytes originalRequest, Bytes originalResponse,
                       List<Exchange> exchanges, int attempted, int omittedExchanges,
                       List<OastToken> issuedTokens, Oob observation, List<String> relatedEvidenceIds) {
    static final int MAX_MESSAGE_BYTES = 64 * 1024;
    static final int MAX_EXCHANGES = 16;
    static final int MAX_CASE_BYTES = 512 * 1024;
    static final String DETECTOR_VERSION = "1";

    FindingEvidence(String id, String captureId, String runId, String source, String detectorId,
                    String detectorVersion, VerificationState state, String observedAt, String rationale,
                    String reproduction, Bytes originalRequest, List<Exchange> exchanges, int attempted, int omitted,
                    List<OastToken> tokens, Oob observation, List<String> related) {
        this(id, captureId, runId, source, detectorId, detectorVersion, state, observedAt, rationale, reproduction,
                originalRequest, Bytes.unavailable(), exchanges, attempted, omitted, tokens, observation, related);
    }

    FindingEvidence {
        exchanges = List.copyOf(exchanges); issuedTokens = List.copyOf(issuedTokens);
        relatedEvidenceIds = List.copyOf(relatedEvidenceIds);
        if (state == null) state = VerificationState.SIGNAL;
    }

    enum Capture { COMPLETE, PREFIX, OMITTED, UNAVAILABLE }
    record Bytes(int originalLength, String sha256, String capturedSha256, String base64, Capture capture) {
        static Bytes unavailable() { return new Bytes(-1, "", "", "", Capture.UNAVAILABLE); }
        static Bytes capture(byte[] bytes) {
            if (bytes == null) return unavailable();
            byte[] prefix = java.util.Arrays.copyOf(bytes, Math.min(bytes.length, MAX_MESSAGE_BYTES));
            return new Bytes(bytes.length, digest(bytes), digest(prefix), Base64.getEncoder().encodeToString(prefix),
                    prefix.length == bytes.length ? Capture.COMPLETE : Capture.PREFIX);
        }
        int retainedBytes() { return base64.length(); }
        Bytes withoutBytes() {
            return capture == Capture.UNAVAILABLE ? this : new Bytes(originalLength, sha256, "", "", Capture.OMITTED);
        }
        byte[] decoded() { return Base64.getDecoder().decode(base64); }
    }

    record Exchange(String id, String runId, String probeId, String method, String url, String decision,
                    boolean dispatchAttempted, long elapsedNanos, String errorType,
                    Bytes plannedRequest, Bytes returnedRequest, Bytes response) {
        int retainedBytes() { return plannedRequest.retainedBytes() + returnedRequest.retainedBytes() + response.retainedBytes(); }
        Exchange withoutBytes() {
            return new Exchange(id, runId, probeId, method, url, decision, dispatchAttempted, elapsedNanos, errorType,
                    plannedRequest.withoutBytes(), returnedRequest.withoutBytes(), response.withoutBytes());
        }
    }
    record OastToken(String payloadId, String testClass, String parameter, boolean dispatchAttempted) {}
    record Oob(String fingerprint, String payloadId, String type, String timestamp, String clientIp, int clientPort,
               String customData, String dnsQueryType, Bytes dnsQuery, String httpProtocol, Bytes httpRequest, Bytes httpResponse, String smtpProtocol, Bytes smtpUtf8) {
        int retainedBytes() { return dnsQuery.retainedBytes() + httpRequest.retainedBytes() + httpResponse.retainedBytes() + smtpUtf8.retainedBytes(); }
        Oob withoutBytes() { return new Oob(fingerprint, payloadId, type, timestamp, clientIp, clientPort, customData,
                dnsQueryType, dnsQuery.withoutBytes(), httpProtocol, httpRequest.withoutBytes(), httpResponse.withoutBytes(), smtpProtocol, smtpUtf8.withoutBytes()); }
    }

    int retainedBytes() { return originalRequest.retainedBytes() + originalResponse.retainedBytes() + exchanges.stream().mapToInt(Exchange::retainedBytes).sum()
            + (observation == null ? 0 : observation.retainedBytes()); }
    boolean complete() {
        boolean oobComplete = observation == null || java.util.stream.Stream.of(observation.dnsQuery(), observation.httpRequest(), observation.httpResponse(), observation.smtpUtf8())
                .allMatch(b -> b.capture() == Capture.COMPLETE || b.capture() == Capture.UNAVAILABLE)
                && java.util.stream.Stream.of(observation.dnsQuery(), observation.httpRequest(), observation.smtpUtf8()).anyMatch(b -> b.capture() == Capture.COMPLETE);
        return oobComplete && (originalResponse.capture() == Capture.UNAVAILABLE || originalResponse.capture() == Capture.COMPLETE)
                && omittedExchanges == 0 && originalRequest.capture() == Capture.COMPLETE
                && exchanges.stream().allMatch(e -> e.plannedRequest.capture() == Capture.COMPLETE
                && (!e.dispatchAttempted || (e.returnedRequest.capture() == Capture.COMPLETE && e.response.capture() == Capture.COMPLETE)));
    }
    FindingEvidence withoutBytes() {
        return new FindingEvidence(id, captureId, runId, source, detectorId, detectorVersion, state, observedAt,
                rationale, reproduction, originalRequest.withoutBytes(), originalResponse.withoutBytes(), exchanges.stream().map(Exchange::withoutBytes).toList(),
                attempted, omittedExchanges, issuedTokens, observation == null ? null : observation.withoutBytes(), relatedEvidenceIds);
    }
    FindingEvidence withOriginalResponse(Bytes response) {
        FindingEvidence evidence = new FindingEvidence(id, captureId, runId, source, detectorId, detectorVersion, state,
                observedAt, rationale, reproduction, originalRequest, response, exchanges, attempted, omittedExchanges,
                issuedTokens, observation, relatedEvidenceIds);
        return evidence.retainedBytes() > MAX_CASE_BYTES ? evidence.withoutBytes() : evidence;
    }

    static FindingEvidence metadata(String detector, VerificationState state, String reason) {
        return new FindingEvidence(UUID.randomUUID().toString(), "", "", "METADATA_ONLY", detector, "unknown", state,
                "", reason, "Original request/response sequence was not retained; reproduce manually in an authorized session.",
                Bytes.unavailable(), List.of(), 0, 0, List.of(), null, List.of());
    }
    static String digest(byte[] bytes) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)); }
        catch (java.security.NoSuchAlgorithmException e) { throw new IllegalStateException(e); }
    }
    static String digest(String value) { return digest(value.getBytes(StandardCharsets.UTF_8)); }

    String describe() {
        StringBuilder out = new StringBuilder("Evidence ID: ").append(id).append("\nState: ").append(state)
                .append("\nSource: ").append(source).append("\nDetector: ").append(detectorId).append(" @ ").append(detectorVersion)
                .append("\nRun: ").append(runId.isEmpty() ? "unknown" : runId).append("\nObserved: ").append(observedAt.isEmpty() ? "unknown" : observedAt)
                .append("\nRationale: ").append(rationale).append("\nReproduction: ").append(reproduction)
                .append("\nAttempted: ").append(attempted).append("; omitted exchanges: ").append(omittedExchanges)
                .append("\nComplete retained sequence: ").append(complete()).append("\nBytes are API observations, not proof of wire delivery or the physical peer.\n");
        for (Exchange e : exchanges) out.append("\n").append(e.probeId).append(" ").append(e.method).append(" ").append(e.url)
                .append(" | ").append(e.decision).append(" | dispatch attempted=").append(e.dispatchAttempted)
                .append(" | elapsed ns=").append(e.elapsedNanos).append("\nRequest: ").append(e.plannedRequest.capture)
                .append(" sha256=").append(e.plannedRequest.sha256).append("\nResponse: ").append(e.response.capture)
                .append(" sha256=").append(e.response.sha256).append('\n');
        if (observation != null) out.append("\nOOB: ").append(observation.type).append(" id=").append(observation.payloadId)
                .append(" from ").append(observation.clientIp).append(':').append(observation.clientPort)
                .append("\nRelated evidence: ").append(relatedEvidenceIds).append('\n');
        return out.toString();
    }
}
