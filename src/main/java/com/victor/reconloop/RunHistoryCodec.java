package com.victor.reconloop;

import java.time.Instant;
import java.util.*;

/** Versioned, bounded, checksummed JSONL. A future or damaged snapshot is never overwritten. */
final class RunHistoryCodec {
    static final int VERSION = 1, MAX_CHARS = 24 * 1024 * 1024, MAX_RECORD_CHARS = 768 * 1024;
    enum Status { ABSENT, CURRENT, UNSUPPORTED, CORRUPT }
    record Loaded(Status status, List<RunRecord> runs) {
        boolean writable() { return status == Status.ABSENT || status == Status.CURRENT; }
    }
    static String encode(List<RunRecord> records) {
        if (records.size() > RunRecord.MAX_RUNS) throw invalid();
        var lines = new ArrayList<String>(); var ids = new HashSet<String>();
        for (var run : records) {
            if (!ids.add(run.id())) throw invalid();
            String line = Json.write(map(run));
            if (line.length() > MAX_RECORD_CHARS) throw invalid();
            read(object(Json.parseStrict(line))); // Writes and restores use the same validation.
            lines.add(line);
        }
        String payload = String.join("\n", lines);
        String out = Json.write(obj("version", VERSION, "count", records.size(), "sha256", FindingEvidence.digest(payload))) + "\n" + payload;
        if (out.length() > MAX_CHARS) throw invalid();
        return out;
    }
    static Loaded decode(String source) {
        if (source == null || source.isEmpty()) return new Loaded(Status.ABSENT, List.of());
        if (source.length() > MAX_CHARS) return new Loaded(Status.CORRUPT, List.of());
        try {
            int split = source.indexOf('\n'); if (split < 0 || split > 1024) throw invalid();
            var header = object(Json.parseStrict(source.substring(0, split)));
            if (number(header, "version", Integer.MAX_VALUE) > VERSION) return new Loaded(Status.UNSUPPORTED, List.of());
            keys(header, "version,count,sha256");
            if (number(header, "version", VERSION) != VERSION) throw invalid();
            int count = number(header, "count", RunRecord.MAX_RUNS);
            String payload = source.substring(split + 1);
            if (!FindingEvidence.digest(payload).equals(hash(header, "sha256", false))) throw invalid();
            String[] lines = payload.isEmpty() ? new String[0] : payload.split("\n", -1);
            if (lines.length != count) throw invalid();
            var runs = new ArrayList<RunRecord>(); var ids = new HashSet<String>();
            for (String line : lines) {
                if (line.length() > MAX_RECORD_CHARS) throw invalid();
                var run = read(object(Json.parseStrict(line))); if (!ids.add(run.id())) throw invalid(); runs.add(run);
            }
            return new Loaded(Status.CURRENT, List.copyOf(runs));
        } catch (RuntimeException invalid) { return new Loaded(Status.CORRUPT, List.of()); }
    }
    static Map<String, Object> map(RunRecord r) {
        var m = r.metrics();
        return obj("id", r.id(), "parent", r.parentId(), "started", r.startedAt(), "finished", r.finishedAt(), "status", r.status().name(),
                "profile", r.profile().name(), "domains", r.scope().domains().stream().sorted().toList(), "cidrs", r.scope().cidrs().stream().sorted().toList(), "scopeTruncated", r.scope().truncated(),
                "limits", List.of(r.limits().global(), r.limits().perHost(), r.limits().perEndpoint(), r.limits().perProbe()),
                "metrics", obj("attempts", str(m.attempts()), "admitted", m.admitted(), "dispatched", str(m.dispatched()), "responses", str(m.responses()),
                        "errors", str(m.errors()), "denied", str(m.denied()), "transportNanos", str(m.transportNanos()), "hosts", m.hosts(), "endpoints", m.endpoints(), "probes", m.probes()),
                "audit", r.audit().stream().map(e -> obj("id", e.id(), "at", e.at(), "kind", e.kind(), "probe", e.probe(), "target", e.target(),
                        "hash", e.requestHash(), "decision", e.decision(), "dispatched", e.dispatched(), "nanos", str(e.elapsedNanos()), "detail", e.detail())).toList(),
                "omittedEvents", str(r.omittedEvents()), "probes", r.probes().stream().map(p -> obj("key", p.key(), "source", p.source(), "probe", p.probe(),
                        "target", p.target(), "parameter", p.parameter(), "encoding", p.encoding(), "limit", p.localLimit(), "status", p.status().name())).toList(),
                "omittedProbes", str(r.omittedProbes()), "findings", r.findings().stream().map(f -> obj("id", f.evidenceId(), "key", f.key(), "state", f.state().name())).toList(),
                "omittedFindings", str(r.omittedFindings()));
    }
    private static RunRecord read(Map<String, Object> r) {
        keys(r, "id,parent,started,finished,status,profile,domains,cidrs,scopeTruncated,limits,metrics,audit,omittedEvents,probes,omittedProbes,findings,omittedFindings");
        String id = uuid(r, "id", false), parent = uuid(r, "parent", true); if (id.equals(parent)) throw invalid();
        String started = time(r, "started", false), finished = time(r, "finished", true);
        RunStatus status = RunStatus.valueOf(text(r, "status", 32));
        if ((status == RunStatus.RUNNING || status == RunStatus.PAUSED || status == RunStatus.PLANNED) != finished.isEmpty()) throw invalid();
        if (!finished.isEmpty() && Instant.parse(finished).isBefore(Instant.parse(started))) throw invalid();
        var values = array(r, "limits", 4); if (values.size() != 4) throw invalid();
        int global = integer(values.get(0), 1_000_000);
        var limits = new ScanRun.RequestLimits(global, integer(values.get(1), global), integer(values.get(2), global), integer(values.get(3), global));
        if (!values.equals(List.of((double)limits.global(), (double)limits.perHost(), (double)limits.perEndpoint(), (double)limits.perProbe()))) throw invalid();
        var m = object(r.get("metrics")); keys(m, "attempts,admitted,dispatched,responses,errors,denied,transportNanos,hosts,endpoints,probes");
        var metrics = new RunRecord.Metrics(decimal(m, "attempts"), number(m, "admitted", global), decimal(m, "dispatched"), decimal(m, "responses"),
                decimal(m, "errors"), decimal(m, "denied"), decimal(m, "transportNanos"), counts(m, "hosts", global), counts(m, "endpoints", global), counts(m, "probes", global));
        if (metrics.dispatched() > metrics.admitted() || metrics.responses() > metrics.dispatched() || metrics.errors() > metrics.dispatched()
                || metrics.responses() + metrics.errors() > metrics.dispatched() || metrics.dispatched() > metrics.attempts()
                || metrics.denied() != metrics.attempts() - metrics.dispatched()) throw invalid();
        var audit = new ArrayList<RunRecord.Event>(); var ids = new HashSet<String>();
        for (Object value : array(r, "audit", RunRecord.MAX_EVENTS)) {
            var e = object(value); keys(e, "id,at,kind,probe,target,hash,decision,dispatched,nanos,detail");
            String eventId = uuid(e, "id", false); if (!ids.add(eventId)) throw invalid();
            String kind = text(e, "kind", 16); if (!Set.of("LIFECYCLE", "REQUEST", "DISPATCH", "PROBE", "FINDING", "CALLBACK").contains(kind)) throw invalid();
            if (!(e.get("dispatched") instanceof Boolean sent)) throw invalid();
            audit.add(new RunRecord.Event(eventId, time(e, "at", false), kind, text(e, "probe", 128), hash(e, "target", true),
                    hash(e, "hash", true), text(e, "decision", 64), sent, decimal(e, "nanos"), text(e, "detail", 128)));
        }
        var probes = new ArrayList<RunRecord.Probe>(); ids.clear();
        for (Object value : array(r, "probes", RunRecord.MAX_PROBES)) {
            var p = object(value); keys(p, "key,source,probe,target,parameter,encoding,limit,status");
            var probe = new RunRecord.Probe(hash(p, "key", false), text(p, "source", 32), text(p, "probe", 128), hash(p, "target", false),
                    text(p, "parameter", 64), text(p, "encoding", 32), number(p, "limit", 1_000_000), RunRecord.ProbeStatus.valueOf(text(p, "status", 32)));
            if (!probe.key().equals(RunRecord.probeKey(probe.source(), probe.probe(), probe.target(), probe.parameter(), probe.encoding())) || !ids.add(probe.key())) throw invalid();
            probes.add(probe);
        }
        var findings = new ArrayList<RunRecord.Finding>(); ids.clear();
        for (Object value : array(r, "findings", RunRecord.MAX_FINDINGS)) {
            var f = object(value); keys(f, "id,key,state"); String fid = uuid(f, "id", false); if (!ids.add(fid)) throw invalid();
            findings.add(new RunRecord.Finding(fid, hash(f, "key", false), VerificationState.valueOf(text(f, "state", 32))));
        }
        if (!(r.get("scopeTruncated") instanceof Boolean scopeTruncated)) throw invalid();
        return new RunRecord(id, parent, started, finished, status, ScanProfile.valueOf(text(r, "profile", 32)),
                new ScopeSnapshot(strings(r, "domains"), strings(r, "cidrs"), scopeTruncated), limits, metrics, audit, decimal(r, "omittedEvents"),
                probes, decimal(r, "omittedProbes"), findings, decimal(r, "omittedFindings"));
    }
    private static Set<String> strings(Map<String, Object> map, String key) {
        var values = new HashSet<String>(); for (Object v : array(map, key, 1024)) {
            if (!(v instanceof String s) || s.isBlank() || s.length() > 253 || !values.add(s)) throw invalid();
        } return values;
    }
    private static Map<String, Integer> counts(Map<String, Object> map, String key, int max) {
        var values = object(map.get(key)); if (values.size() > 256) throw invalid();
        var out = new HashMap<String, Integer>(); long total = 0;
        for (var e : values.entrySet()) { if (e.getKey().length() > 128) throw invalid(); int n = integer(e.getValue(), max); total += n; out.put(e.getKey(), n); }
        if (total > max) throw invalid(); return Map.copyOf(out);
    }
    private static String str(long value) { return Long.toString(value); }
    private static long decimal(Map<String, Object> m, String key) {
        String value = text(m, key, 19); if (!value.matches("0|[1-9][0-9]*")) throw invalid(); return Long.parseLong(value);
    }
    private static String time(Map<String, Object> m, String key, boolean empty) { String s = text(m, key, 64); if (!(empty && s.isEmpty())) Instant.parse(s); return s; }
    private static String uuid(Map<String, Object> m, String key, boolean empty) { String s = text(m, key, 36); if (!(empty && s.isEmpty()) && !UUID.fromString(s).toString().equals(s)) throw invalid(); return s; }
    private static String hash(Map<String, Object> m, String key, boolean empty) { String s = text(m, key, 64); if (!(empty && s.isEmpty()) && !s.matches("[0-9a-f]{64}")) throw invalid(); return s; }
    private static int number(Map<String, Object> m, String key, int max) { return integer(m.get(key), max); }
    private static int integer(Object v, int max) { if (!(v instanceof Double d) || !Double.isFinite(d) || d != Math.rint(d) || d < 0 || d > max) throw invalid(); return d.intValue(); }
    private static String text(Map<String, Object> m, String key, int max) { if (!(m.get(key) instanceof String s) || s.length() > max) throw invalid(); return s; }
    private static List<Object> array(Map<String, Object> m, String key, int max) { var a = Json.asArray(m.get(key)); if (a == null || a.size() > max) throw invalid(); return a; }
    private static Map<String, Object> object(Object value) { var m = Json.asObject(value); if (m == null) throw invalid(); return m; }
    private static void keys(Map<String, Object> m, String fields) { if (!m.keySet().equals(Set.of(fields.split(",")))) throw invalid(); }
    private static IllegalArgumentException invalid() { return new IllegalArgumentException("invalid scan-run snapshot"); }
    private static Map<String, Object> obj(Object... pairs) { var m = new LinkedHashMap<String, Object>(); for (int i = 0; i < pairs.length; i += 2) m.put((String)pairs[i], pairs[i+1]); return m; }
}
