package com.victor.reconloop;

import java.net.URI;
import java.util.*;

/** Immutable history, never a dispatch capability. Bodies, credentials and query values stay out. */
record RunRecord(String id, String parentId, String startedAt, String finishedAt, RunStatus status,
                 ScanProfile profile, ScopeSnapshot scope, ScanRun.RequestLimits limits,
                 Metrics metrics, List<Event> audit, long omittedEvents, List<Probe> probes,
                 long omittedProbes, List<Finding> findings, long omittedFindings) {
    static final int MAX_RUNS = 30, MAX_EVENTS = 512, MAX_PROBES = 256, MAX_FINDINGS = 500;
    record Metrics(long attempts, int admitted, long dispatched, long responses, long errors,
                   long denied, long transportNanos, Map<String, Integer> hosts,
                   Map<String, Integer> endpoints, Map<String, Integer> probes) {
        long inFlight() { return dispatched - responses - errors; }
    }
    record Event(String id, String at, String kind, String probe, String target, String requestHash,
                 String decision, boolean dispatched, long elapsedNanos, String detail) {}
    enum ProbeStatus { IN_PROGRESS, SKIPPED, CHECKED, FINDING, FAILED, INCONCLUSIVE }
    record Probe(String key, String source, String probe, String target, String parameter,
                 String encoding, int localLimit, ProbeStatus status) {
        boolean retryable() { return status == ProbeStatus.FAILED || status == ProbeStatus.INCONCLUSIVE; }
    }
    record Finding(String evidenceId, String key, VerificationState state) {}

    RunRecord {
        audit = List.copyOf(audit); probes = List.copyOf(probes); findings = List.copyOf(findings);
    }
    RunRecord interrupted() {
        boolean interrupted = status == RunStatus.RUNNING || status == RunStatus.PAUSED || status == RunStatus.PLANNED;
        boolean pending = probes.stream().anyMatch(p -> p.status() == ProbeStatus.IN_PROGRESS);
        if (!interrupted && !pending) return this;
        var restoredProbes = probes.stream().map(p -> p.status() == ProbeStatus.IN_PROGRESS
                ? new Probe(p.key(), p.source(), p.probe(), p.target(), p.parameter(), p.encoding(), p.localLimit(), ProbeStatus.INCONCLUSIVE) : p).toList();
        return new RunRecord(id, parentId, startedAt, interrupted ? java.time.Instant.now().toString() : finishedAt,
                interrupted ? RunStatus.INTERRUPTED : status, profile, scope, limits, metrics, audit, omittedEvents,
                restoredProbes, omittedProbes, findings, omittedFindings);
    }
    Set<String> findingKeys() {
        Set<String> keys = new HashSet<>();
        findings.stream().filter(f -> f.state() != VerificationState.REJECTED).forEach(f -> keys.add(f.key()));
        return Set.copyOf(keys);
    }
    static String target(String method, String url) { return FindingEvidence.digest(method + "\0" + url); }
    static String pointIdentity(InsertionPoint point) {
        return FindingEvidence.digest(point.kind() + "\0" + point.paramType() + "\0" + point.name() + "\0" + point.index());
    }
    static String findingKey(ReconModel.ActiveRow row) {
        var evidence = row.evidenceRecord();
        return FindingEvidence.digest(evidence.detectorId() + "\0" + evidence.detectorVersion() + "\0"
                + row.testClass() + "\0" + row.parameter() + "\0"
                + (evidence.exchanges().isEmpty() ? "" : evidence.exchanges().getFirst().method()) + "\0" + route(row.url()));
    }
    private static String route(String url) {
        String route = url;
        try {
            URI uri = URI.create(route);
            var names = new TreeSet<String>();
            if (uri.getRawQuery() != null) for (String part : uri.getRawQuery().split("&")) names.add(part.split("=", 2)[0]);
            route = uri.getScheme().toLowerCase(Locale.ROOT) + "://" + uri.getHost().toLowerCase(Locale.ROOT)
                    + ":" + (uri.getPort() < 0 ? ("https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80) : uri.getPort())
                    + (uri.getRawPath() == null || uri.getRawPath().isEmpty() ? "/" : uri.getRawPath()) + "?" + names;
        } catch (RuntimeException ignored) { /* Hash the opaque identity, never persist it as text. */ }
        return route;
    }
    static Finding passiveFinding(ReconModel.FindingRow row) {
        String identity = row.provider() + "\0" + row.rule() + "\0" + row.location() + "\0" + route(row.url());
        return new Finding(UUID.nameUUIDFromBytes((row.runId() + identity).getBytes(java.nio.charset.StandardCharsets.UTF_8)).toString(),
                FindingEvidence.digest(identity), VerificationState.SIGNAL);
    }
    RunRecord withFinding(Finding finding, String kind, String detector) {
        var values = new LinkedHashMap<String, Finding>(); findings.forEach(f -> values.put(f.evidenceId(), f));
        long omitted = omittedFindings;
        if (values.containsKey(finding.evidenceId()) || values.size() < MAX_FINDINGS) values.put(finding.evidenceId(), finding); else omitted++;
        var events = new ArrayList<>(audit); long dropped = omittedEvents;
        if (events.size() == MAX_EVENTS) { events.removeFirst(); dropped++; }
        events.add(new Event(UUID.randomUUID().toString(), java.time.Instant.now().toString(), kind, detector, "", "", finding.state().name(), false, 0, finding.evidenceId()));
        return new RunRecord(id, parentId, startedAt, finishedAt, status, profile, scope, limits, metrics, events, dropped, probes, omittedProbes, List.copyOf(values.values()), omitted);
    }
    static String probeKey(String source, String probe, String target, String parameter, String encoding) {
        return FindingEvidence.digest(source + "\0" + probe + "\0" + target + "\0" + parameter + "\0" + encoding);
    }
}
