package com.victor.reconloop;

import java.util.*;

/** Atomic JSONL snapshot: a version/count/digest header followed by strictly validated record lines. */
final class ActiveEvidenceCodec {
    static final int VERSION = 1;
    static final int MAX_CHARS = 24 * 1024 * 1024;
    static final int MAX_RECORD_CHARS = 2 * 1024 * 1024;
    enum Status { ABSENT, CURRENT, MIGRATED, UNSUPPORTED, CORRUPT }
    record Loaded(Status status, List<ReconModel.ActiveRow> rows) {
        boolean writable() { return status == Status.ABSENT || status == Status.CURRENT || status == Status.MIGRATED; }
    }

    static String encode(List<ReconModel.ActiveRow> rows) {
        if (rows.size() > ReconModel.ActiveTableModel.MAX_ROWS) throw invalid();
        List<String> lines = new ArrayList<>();
        Set<String> ids = new HashSet<>(); int retained = 0, chars = 0;
        for (var row : rows) {
            retained += row.evidenceRecord().retainedBytes();
            if (retained > ReconModel.ActiveTableModel.MAX_RETAINED_BYTES) throw invalid();
            if (!ids.add(row.evidenceRecord().id())) throw invalid();
            Map<String, Object> object = rowMap(row);
            readRow(object);
            String line = Json.write(object);
            if (line.length() > MAX_RECORD_CHARS) throw invalid();
            // One validation path for writes/restores. Never write a snapshot this version cannot read.
            chars += line.length() + 1;
            if (chars > MAX_CHARS - 1024) throw invalid();
            lines.add(line);
        }
        String payload = String.join("\n", lines);
        String header = Json.write(obj("schemaVersion", VERSION, "recordCount", rows.size(), "payloadSha256", FindingEvidence.digest(payload)));
        String snapshot = header + "\n" + payload;
        if (snapshot.length() > MAX_CHARS) throw invalid();
        return snapshot;
    }

    static Loaded decode(String snapshot) {
        if (snapshot == null || snapshot.isEmpty()) return new Loaded(Status.ABSENT, List.of());
        if (snapshot.length() > MAX_CHARS) return new Loaded(Status.CORRUPT, List.of());
        try {
            int split = snapshot.indexOf('\n');
            if (split < 0 || split > 1024) throw invalid();
            Map<String, Object> header = map(Json.parseStrict(snapshot.substring(0, split)));
            int version = integer(header, "schemaVersion", 0, Integer.MAX_VALUE);
            if (version > VERSION) return new Loaded(Status.UNSUPPORTED, List.of());
            keys(header, version == 0 ? "schemaVersion,recordCount" : "schemaVersion,recordCount,payloadSha256");
            int count = integer(header, "recordCount", 0, ReconModel.ActiveTableModel.MAX_ROWS);
            String payload = snapshot.substring(split + 1);
            if (version == VERSION && !FindingEvidence.digest(payload).equals(text(header, "payloadSha256", 64))) throw invalid();
            String[] lines = payload.isEmpty() ? new String[0] : payload.split("\n", -1);
            if (lines.length != count) throw invalid();
            List<ReconModel.ActiveRow> rows = new ArrayList<>(); Set<String> ids = new HashSet<>();
            int retained = 0;
            for (String line : lines) {
                if (line.length() > MAX_RECORD_CHARS) throw invalid();
                Map<String, Object> record = map(Json.parseStrict(line));
                ReconModel.ActiveRow row = version == 0 ? legacy(record) : readRow(record);
                if (!ids.add(row.evidenceRecord().id())) throw invalid();
                retained += row.evidenceRecord().retainedBytes();
                if (retained > ReconModel.ActiveTableModel.MAX_RETAINED_BYTES) throw invalid();
                rows.add(row);
            }
            return new Loaded(version == 0 ? Status.MIGRATED : Status.CURRENT, List.copyOf(rows));
        } catch (RuntimeException invalid) { return new Loaded(Status.CORRUPT, List.of()); }
    }

    private static ReconModel.ActiveRow legacy(Map<String, Object> row) {
        keys(row, row.containsKey("confirmed") ? "severity,testClass,parameter,status,evidence,url,confirmed" : "severity,testClass,parameter,status,evidence,url");
        // Compatibility import, not a claim that pre-evidence releases retained active history.
        Object confirmed = row.get("confirmed");
        if (row.containsKey("confirmed") && !(confirmed instanceof Boolean)) throw invalid();
        VerificationState state = Boolean.TRUE.equals(confirmed) ? VerificationState.REPRODUCED : VerificationState.SIGNAL;
        FindingEvidence evidence = FindingEvidence.metadata(text(row, "testClass", 256), state,
                "Migrated legacy observation. A legacy true flag means reproduced detector signal; run, version and byte evidence are unavailable.");
        return new ReconModel.ActiveRow(text(row, "severity", 32), text(row, "testClass", 256), text(row, "parameter", 4096),
                text(row, "status", 128), text(row, "evidence", 65536), text(row, "url", 65536), evidence);
    }

    static Map<String, Object> rowMap(ReconModel.ActiveRow row) {
        return obj("severity", row.severity(), "testClass", row.testClass(), "parameter", row.parameter(), "status", row.status(),
                "evidence", row.evidence(), "url", row.url(), "provenance", evidenceMap(row.evidenceRecord()));
    }
    static Map<String, Object> evidenceMap(FindingEvidence e) {
        return obj("id", e.id(), "captureId", e.captureId(), "runId", e.runId(), "source", e.source(), "detectorId", e.detectorId(),
                "detectorVersion", e.detectorVersion(), "verificationState", e.state().name(), "observedAt", e.observedAt(),
                "rationale", e.rationale(), "reproduction", e.reproduction(), "originalRequest", bytesMap(e.originalRequest()), "originalResponse", bytesMap(e.originalResponse()),
                "attempted", e.attempted(), "omittedExchanges", e.omittedExchanges(),
                "exchanges", e.exchanges().stream().map(ActiveEvidenceCodec::exchangeMap).toList(),
                "issuedTokens", e.issuedTokens().stream().map(t -> obj("payloadId", t.payloadId(), "testClass", t.testClass(), "parameter", t.parameter(), "dispatchAttempted", t.dispatchAttempted())).toList(),
                "observation", e.observation() == null ? null : oobMap(e.observation()), "relatedEvidenceIds", e.relatedEvidenceIds());
    }
    private static Map<String, Object> bytesMap(FindingEvidence.Bytes b) {
        return obj("originalLength", b.originalLength(), "sha256", b.sha256(), "capturedSha256", b.capturedSha256(), "base64", b.base64(), "capture", b.capture().name());
    }
    private static Map<String, Object> exchangeMap(FindingEvidence.Exchange e) {
        return obj("id", e.id(), "runId", e.runId(), "probeId", e.probeId(), "method", e.method(), "url", e.url(), "decision", e.decision(),
                "dispatchAttempted", e.dispatchAttempted(), "elapsedNanos", Long.toString(e.elapsedNanos()), "errorType", e.errorType(),
                "plannedRequest", bytesMap(e.plannedRequest()), "returnedRequest", bytesMap(e.returnedRequest()), "response", bytesMap(e.response()));
    }
    private static Map<String, Object> oobMap(FindingEvidence.Oob o) {
        return obj("fingerprint", o.fingerprint(), "payloadId", o.payloadId(), "type", o.type(), "timestamp", o.timestamp(), "clientIp", o.clientIp(),
                "clientPort", o.clientPort(), "customData", o.customData(), "dnsQueryType", o.dnsQueryType(), "dnsQuery", bytesMap(o.dnsQuery()),
                "httpProtocol", o.httpProtocol(), "httpRequest", bytesMap(o.httpRequest()), "httpResponse", bytesMap(o.httpResponse()), "smtpProtocol", o.smtpProtocol(), "smtpUtf8", bytesMap(o.smtpUtf8()));
    }

    private static ReconModel.ActiveRow readRow(Map<String, Object> row) {
        keys(row, "severity,testClass,parameter,status,evidence,url,provenance");
        return new ReconModel.ActiveRow(text(row, "severity", 32), text(row, "testClass", 256), text(row, "parameter", 4096),
                text(row, "status", 128), text(row, "evidence", 65536), text(row, "url", 65536), readEvidence(map(row.get("provenance"))));
    }
    private static FindingEvidence readEvidence(Map<String, Object> o) {
        keys(o, "id,captureId,runId,source,detectorId,detectorVersion,verificationState,observedAt,rationale,reproduction,originalRequest,originalResponse,attempted,omittedExchanges,exchanges,issuedTokens,observation,relatedEvidenceIds");
        String id = uuid(o, "id", false), capture = uuid(o, "captureId", true), run = uuid(o, "runId", true);
        String source = text(o, "source", 64);
        if (!Set.of("NATIVE_ACTIVE", "CORPUS", "NATIVE_HELPER", "OOB", "METADATA_ONLY").contains(source)) throw invalid();
        String observed = timestamp(o, "observedAt");
        List<FindingEvidence.Exchange> exchanges = new ArrayList<>(); Set<String> exchangeIds = new HashSet<>();
        for (Object item : list(o, "exchanges", FindingEvidence.MAX_EXCHANGES)) {
            Map<String, Object> e = map(item);
            keys(e, "id,runId,probeId,method,url,decision,dispatchAttempted,elapsedNanos,errorType,plannedRequest,returnedRequest,response");
            String exchangeId = uuid(e, "id", false), exchangeRun = uuid(e, "runId", false);
            if (!exchangeIds.add(exchangeId) || !exchangeRun.equals(run)) throw invalid();
            String elapsed = text(e, "elapsedNanos", 19);
            if (!elapsed.matches("0|[1-9][0-9]*")) throw invalid();
            long nanos = Long.parseLong(elapsed);
            String decision = text(e, "decision", 64); RequestPolicy.DecisionCode.valueOf(decision);
            boolean dispatched = bool(e, "dispatchAttempted");
            FindingEvidence.Bytes planned = readBytes(map(e.get("plannedRequest"))), returned = readBytes(map(e.get("returnedRequest"))), response = readBytes(map(e.get("response")));
            if (!dispatched && (returned.capture() != FindingEvidence.Capture.UNAVAILABLE || response.capture() != FindingEvidence.Capture.UNAVAILABLE)) throw invalid();
            exchanges.add(new FindingEvidence.Exchange(exchangeId, exchangeRun, text(e, "probeId", 256), text(e, "method", 32),
                    text(e, "url", 65536), decision, dispatched, nanos, text(e, "errorType", 256), planned, returned, response));
        }
        int attempted = integer(o, "attempted", 0, 1_000_000), omitted = integer(o, "omittedExchanges", 0, 1_000_000);
        if ((long) omitted + exchanges.size() != attempted) throw invalid();
        List<FindingEvidence.OastToken> tokens = new ArrayList<>();
        for (Object item : list(o, "issuedTokens", 64)) {
            Map<String, Object> token = map(item);
            keys(token, "payloadId,testClass,parameter,dispatchAttempted");
            tokens.add(new FindingEvidence.OastToken(text(token, "payloadId", 512), text(token, "testClass", 256), text(token, "parameter", 4096), bool(token, "dispatchAttempted")));
        }
        List<String> related = new ArrayList<>();
        for (Object item : list(o, "relatedEvidenceIds", 64)) { if (!(item instanceof String value) || !validUuid(value)) throw invalid(); related.add(value); }
        FindingEvidence.Oob observation = null;
        if (o.get("observation") != null) {
            Map<String, Object> event = map(o.get("observation"));
            keys(event, "fingerprint,payloadId,type,timestamp,clientIp,clientPort,customData,dnsQueryType,dnsQuery,httpProtocol,httpRequest,httpResponse,smtpProtocol,smtpUtf8");
            String fingerprint = text(event, "fingerprint", 64); if (!hash(fingerprint)) throw invalid();
            observation = new FindingEvidence.Oob(fingerprint, text(event, "payloadId", 512), text(event, "type", 64), timestamp(event, "timestamp"),
                    text(event, "clientIp", 128), integer(event, "clientPort", 0, 65535), text(event, "customData", 65536), text(event, "dnsQueryType", 64),
                    readBytes(map(event.get("dnsQuery"))), text(event, "httpProtocol", 64), readBytes(map(event.get("httpRequest"))), readBytes(map(event.get("httpResponse"))),
                    text(event, "smtpProtocol", 64), readBytes(map(event.get("smtpUtf8"))));
        }
        FindingEvidence evidence = new FindingEvidence(id, capture, run, source, text(o, "detectorId", 256), text(o, "detectorVersion", 128),
                VerificationState.valueOf(text(o, "verificationState", 64)), observed, text(o, "rationale", 65536), text(o, "reproduction", 65536),
                readBytes(map(o.get("originalRequest"))), readBytes(map(o.get("originalResponse"))), exchanges, attempted, omitted, tokens, observation, related);
        if (evidence.retainedBytes() > FindingEvidence.MAX_CASE_BYTES) throw invalid();
        return evidence;
    }
    private static FindingEvidence.Bytes readBytes(Map<String, Object> o) {
        keys(o, "originalLength,sha256,capturedSha256,base64,capture");
        int length = integer(o, "originalLength", -1, Integer.MAX_VALUE);
        String sha = text(o, "sha256", 64), capturedSha = text(o, "capturedSha256", 64);
        String base64 = text(o, "base64", ((FindingEvidence.MAX_MESSAGE_BYTES + 2) / 3) * 4);
        FindingEvidence.Capture capture = FindingEvidence.Capture.valueOf(text(o, "capture", 32));
        byte[] bytes = Base64.getDecoder().decode(base64);
        if (bytes.length > FindingEvidence.MAX_MESSAGE_BYTES || !Base64.getEncoder().encodeToString(bytes).equals(base64)) throw invalid();
        if (capture == FindingEvidence.Capture.UNAVAILABLE) {
            if (length != -1 || !sha.isEmpty() || !capturedSha.isEmpty() || !base64.isEmpty()) throw invalid();
        } else {
            if (length < 0 || !hash(sha)) throw invalid();
            if (capture == FindingEvidence.Capture.OMITTED) {
                if (!base64.isEmpty() || !capturedSha.isEmpty()) throw invalid();
            } else {
                if (!hash(capturedSha) || !FindingEvidence.digest(bytes).equals(capturedSha)) throw invalid();
                if (capture == FindingEvidence.Capture.COMPLETE && (bytes.length != length || !sha.equals(capturedSha))) throw invalid();
                if (capture == FindingEvidence.Capture.PREFIX && (bytes.length == 0 || bytes.length >= length)) throw invalid();
            }
        }
        return new FindingEvidence.Bytes(length, sha, capturedSha, base64, capture);
    }
    private static void keys(Map<String, Object> object, String fields) {
        if (!object.keySet().equals(Set.of(fields.split(",")))) throw invalid();
    }
    private static boolean hash(String value) { return value.matches("[0-9a-f]{64}"); }
    private static String timestamp(Map<String, Object> o, String key) {
        String value = text(o, key, 64); if (!value.isEmpty()) java.time.Instant.parse(value); return value;
    }
    private static String uuid(Map<String, Object> o, String key, boolean empty) {
        String value = text(o, key, 36); if (!(empty && value.isEmpty()) && !validUuid(value)) throw invalid(); return value;
    }
    private static boolean validUuid(String value) {
        try { return UUID.fromString(value).toString().equals(value); } catch (RuntimeException invalid) { return false; }
    }
    private static Map<String, Object> map(Object object) {
        Map<String, Object> map = Json.asObject(object); if (map == null) throw invalid(); return map;
    }
    private static List<Object> list(Map<String, Object> o, String key, int max) {
        List<Object> list = Json.asArray(o.get(key)); if (list == null || list.size() > max) throw invalid(); return list;
    }
    private static String text(Map<String, Object> o, String key, int max) {
        if (!(o.get(key) instanceof String value) || value.length() > max) throw invalid(); return value;
    }
    private static boolean bool(Map<String, Object> o, String key) {
        if (!(o.get(key) instanceof Boolean value)) throw invalid(); return value;
    }
    private static int integer(Map<String, Object> o, String key, int min, int max) {
        if (!(o.get(key) instanceof Number value)) throw invalid();
        double number = value.doubleValue();
        if (!Double.isFinite(number) || number != Math.rint(number) || number < min || number > max) throw invalid(); return (int) number;
    }
    private static Map<String, Object> obj(Object... fields) {
        Map<String, Object> out = new LinkedHashMap<>();
        for (int i = 0; i < fields.length; i += 2) out.put((String) fields[i], fields[i + 1]); return out;
    }
    private static IllegalArgumentException invalid() { return new IllegalArgumentException("Invalid or unsupported evidence snapshot"); }
}
