package com.victor.reconloop;

import burp.api.montoya.collaborator.Interaction;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.function.Supplier;

/** Links callbacks only to an explicitly issued payload whose API dispatch was attempted. */
final class OobEvidence {
    static FindingEvidence.Oob capture(Interaction interaction) {
        var dns = interaction.dnsDetails().orElse(null);
        var http = interaction.httpDetails().orElse(null);
        var smtp = interaction.smtpDetails().orElse(null);
        var dnsBytes = EvidenceCapture.bytes(() -> dns.query().getBytes());
        var request = EvidenceCapture.bytes(() -> http.requestResponse().request().toByteArray().getBytes());
        var response = EvidenceCapture.bytes(() -> http.requestResponse().response().toByteArray().getBytes());
        var transcript = EvidenceCapture.bytes(() -> smtp.conversation().getBytes(StandardCharsets.UTF_8));
        String id = text(() -> interaction.id().toString()), type = text(() -> interaction.type().toString());
        String stamp = text(() -> interaction.timeStamp().toInstant().toString());
        String ip = text(() -> interaction.clientIp().getHostAddress());
        int port = interaction.clientPort();
        String custom = interaction.customData().orElse("");
        String dnsType = text(() -> dns.queryType().toString()), httpProtocol = text(() -> http.protocol().toString()), smtpProtocol = text(() -> smtp.protocol().toString());
        String identity = Json.write(List.of(id, type, stamp, ip, port, custom, dnsType, httpProtocol, smtpProtocol, dnsBytes.sha256(), request.sha256(), response.sha256(), transcript.sha256()));
        return new FindingEvidence.Oob(FindingEvidence.digest(identity), id, type, stamp, ip, port, custom,
                dnsType, dnsBytes, httpProtocol, request, response, smtpProtocol, transcript);
    }

    static ReconModel.ActiveRow link(FindingEvidence.Oob event, List<ReconModel.ActiveRow> rows) {
        String captureId = "";
        if (event.customData().startsWith("AC2|")) {
            String candidate = event.customData().substring(4);
            try { if (UUID.fromString(candidate).toString().equals(candidate)) captureId = candidate; }
            catch (IllegalArgumentException malformed) { /* unlinked observation */ }
        }
        List<ReconModel.ActiveRow> parents = new ArrayList<>();
        for (var row : rows) {
            var evidence = row.evidenceRecord();
            if (!captureId.isEmpty() && captureId.equals(evidence.captureId()) && !evidence.runId().isEmpty()
                    && evidence.observation() == null && evidence.issuedTokens().stream()
                    .anyMatch(t -> t.dispatchAttempted() && t.payloadId().equals(event.payloadId()))) parents.add(row);
            if (parents.size() == 64) break;
        }
        if (!parents.isEmpty()) {
            String run = parents.getFirst().evidenceRecord().runId();
            if (parents.stream().anyMatch(p -> !p.evidenceRecord().runId().equals(run))) parents.clear();
        }
        VerificationState state = parents.isEmpty() ? VerificationState.CANDIDATE : VerificationState.CONFIRMED;
        String reason = parents.isEmpty()
                ? "Observed callback without a retained, dispatched payload association. Target/run provenance is unverified."
                : "Observed " + event.type() + " callback for the issued payload associated with " + parents.size()
                + " retained finding(s). This confirms the interaction, not browser execution or exploit impact; shared corpus variants remain ambiguous.";
        Map<String, FindingEvidence.Exchange> exchanges = new LinkedHashMap<>();
        Set<String> groups = new HashSet<>(); int omitted = 0;
        for (var parent : parents) {
            var evidence = parent.evidenceRecord();
            String group = evidence.captureId() + evidence.exchanges().stream().map(FindingEvidence.Exchange::id).toList();
            if (groups.add(group)) omitted += evidence.omittedExchanges();
            for (var exchange : evidence.exchanges()) exchanges.putIfAbsent(exchange.id(), exchange);
        }
        int attempted = exchanges.size() + omitted;
        omitted += Math.max(0, exchanges.size() - FindingEvidence.MAX_EXCHANGES);
        var first = parents.isEmpty() ? null : parents.getFirst();
        var record = new FindingEvidence(UUID.nameUUIDFromBytes(event.fingerprint().getBytes(StandardCharsets.US_ASCII)).toString(), captureId,
                first == null ? "" : first.evidenceRecord().runId(), "OOB", "collaborator-interaction", FindingEvidence.DETECTOR_VERSION,
                state, event.timestamp(), reason, "Inspect the recorded interaction and associated request cases. Reproduction requires a fresh OAST identifier and current authorization; restore never polls or replays.",
                first == null ? FindingEvidence.Bytes.unavailable() : first.evidenceRecord().originalRequest(),
                exchanges.values().stream().limit(FindingEvidence.MAX_EXCHANGES).toList(), attempted, omitted,
                List.of(), event, parents.stream().map(r -> r.evidenceRecord().id()).toList());
        if (first != null) record = record.withOriginalResponse(first.evidenceRecord().originalResponse());
        if (record.retainedBytes() > FindingEvidence.MAX_CASE_BYTES) record = record.withoutBytes();
        return new ReconModel.ActiveRow(parents.isEmpty() ? "INFO" : "HIGH", first == null ? "OOB-unlinked" : first.testClass() + "-OOB",
                first == null ? "unknown" : first.parameter(), state.displayLabel(), reason, first == null ? "" : first.url(), record);
    }

    private static String text(Supplier<String> read) {
        try { String text = read.get(); return text == null ? "" : text; }
        catch (RuntimeException unavailable) { return ""; }
    }
}
