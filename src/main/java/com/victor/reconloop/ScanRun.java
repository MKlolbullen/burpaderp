package com.victor.reconloop;

import java.net.URI;
import java.time.Instant;
import java.util.HashMap;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Run-scoped ownership for request accounting and cooperative cancellation.
 *
 * <p>Request admission is hierarchical: every dispatch must fit the global, per-host,
 * per-endpoint, and per-probe limits atomically. This prevents one noisy endpoint or probe from
 * monopolising the whole run while preserving one hard global ceiling.
 */
final class ScanRun {
    enum Quota {
        GLOBAL,
        HOST,
        ENDPOINT,
        PROBE
    }

    record RequestLimits(int global, int perHost, int perEndpoint, int perProbe) {
        RequestLimits {
            global = Math.max(0, global);
            perHost = clamp(perHost, global);
            perEndpoint = clamp(perEndpoint, global);
            perProbe = clamp(perProbe, global);
        }

        static RequestLimits globalOnly(int global) {
            int value = Math.max(0, global);
            return new RequestLimits(value, value, value, value);
        }

        private static int clamp(int value, int global) {
            if (global == 0) return 0;
            return Math.min(global, Math.max(1, value));
        }
    }

    record Allocation(boolean allowed, Quota exhaustedQuota, String key, int used, int limit) {
        static Allocation granted() {
            return new Allocation(true, null, "", 0, 0);
        }

        static Allocation denied(Quota quota, String key, int used, int limit) {
            return new Allocation(false, quota, key == null ? "" : key, used, limit);
        }
    }

    private String parentId = "";
    private long attempts, dispatched, responses, errors, denied, transportNanos, omittedEvents, omittedProbes, omittedFindings;
    private final List<RunRecord.Event> audit = new ArrayList<>();
    private final Map<String, RunRecord.Probe> probes = new LinkedHashMap<>();
    private final Map<String, RunRecord.Finding> findings = new LinkedHashMap<>();
    private final UUID id;
    private final Instant startedAt;
    private final ScanProfile profile;
    private final ScopeSnapshot scope;
    private final RequestLimits requestLimits;
    private final RequestBudget requestBudget;
    private final Map<String, Integer> hostUsage = new HashMap<>();
    private final Map<String, Integer> endpointUsage = new HashMap<>();
    private final Map<String, Integer> probeUsage = new HashMap<>();
    private final AtomicReference<RunStatus> status = new AtomicReference<>(RunStatus.PLANNED);
    private final AtomicReference<Instant> finishedAt = new AtomicReference<>();
    private final AtomicReference<String> failureReason = new AtomicReference<>();

    private ScanRun(UUID id, Instant startedAt, ScanProfile profile, ScopeSnapshot scope, RequestLimits limits) {
        this.id = Objects.requireNonNull(id, "id");
        this.startedAt = Objects.requireNonNull(startedAt, "startedAt");
        this.profile = Objects.requireNonNull(profile, "profile");
        this.scope = Objects.requireNonNull(scope, "scope");
        this.requestLimits = Objects.requireNonNull(limits, "limits");
        this.requestBudget = new RequestBudget(limits.global());
    }

    static ScanRun begin(ScanProfile profile, ScopeSnapshot scope, int requestLimit) {
        return begin(profile, scope, RequestLimits.globalOnly(requestLimit));
    }

    static ScanRun begin(ScanProfile profile, ScopeSnapshot scope, RequestLimits limits) {
        ScanRun run = new ScanRun(UUID.randomUUID(), Instant.now(), profile,
                scope == null ? ScopeSnapshot.empty() : scope,
                limits == null ? RequestLimits.globalOnly(0) : limits);
        run.start();
        run.event("LIFECYCLE", "", "", "", "RUNNING", false, 0, "");
        return run;
    }

    UUID id() { return id; }
    Instant startedAt() { return startedAt; }
    ScanProfile profile() { return profile; }
    ScopeSnapshot scope() { return scope; }
    RequestLimits requestLimits() { return requestLimits; }
    RequestBudget requestBudget() { return requestBudget; }
    RunStatus status() { return status.get(); }
    Instant finishedAt() { return finishedAt.get(); }
    String failureReason() { return failureReason.get(); }

    /**
     * Atomically reserves capacity across every quota dimension for one planned request.
     *
     * <p>No counters are changed unless all four quota checks pass. Endpoint identity deliberately
     * ignores the query string so parameter mutations of the same route share one endpoint quota.
     */
    synchronized Allocation tryAcquire(RequestPolicy.PlannedRequest request) {
        if (!isRunning() || request == null) return Allocation.denied(Quota.GLOBAL, "", requestBudget.used(), requestLimits.global());

        String host = hostKey(request.url());
        String endpoint = endpointKey(request.method(), request.url());
        String probe = request.probeId() == null || request.probeId().isBlank()
                ? "unspecified" : request.probeId();

        int globalUsed = requestBudget.used();
        if (globalUsed >= requestLimits.global()) {
            return Allocation.denied(Quota.GLOBAL, "global", globalUsed, requestLimits.global());
        }

        int hostUsed = hostUsage.getOrDefault(host, 0);
        if (hostUsed >= requestLimits.perHost()) {
            return Allocation.denied(Quota.HOST, host, hostUsed, requestLimits.perHost());
        }

        int endpointUsed = endpointUsage.getOrDefault(endpoint, 0);
        if (endpointUsed >= requestLimits.perEndpoint()) {
            return Allocation.denied(Quota.ENDPOINT, endpoint, endpointUsed, requestLimits.perEndpoint());
        }

        int probeUsed = probeUsage.getOrDefault(probe, 0);
        if (probeUsed >= requestLimits.perProbe()) {
            return Allocation.denied(Quota.PROBE, probe, probeUsed, requestLimits.perProbe());
        }

        if (!requestBudget.tryAcquire()) {
            return Allocation.denied(Quota.GLOBAL, "global", requestBudget.used(), requestLimits.global());
        }

        hostUsage.put(host, hostUsed + 1);
        endpointUsage.put(endpoint, endpointUsed + 1);
        probeUsage.put(probe, probeUsed + 1);
        return Allocation.granted();
    }

    synchronized int hostRequests(String host) {
        return hostUsage.getOrDefault(normalizeHost(host), 0);
    }

    /** Read-only planning uses an independent ledger; never reserves live tokens. */
    synchronized ScanRun previewCopy() {
        ScanRun copy = new ScanRun(id, startedAt, profile, scope, requestLimits);
        for (int i = 0, used = requestBudget.used(); i < used; i++) copy.requestBudget.tryAcquire();
        copy.hostUsage.putAll(hostUsage);
        copy.endpointUsage.putAll(endpointUsage);
        copy.probeUsage.putAll(probeUsage);
        copy.status.set(status.get());
        return copy;
    }

    synchronized int endpointRequests(String method, String url) {
        return endpointUsage.getOrDefault(endpointKey(method, url), 0);
    }

    synchronized int probeRequests(String probeId) {
        String key = probeId == null || probeId.isBlank() ? "unspecified" : probeId;
        return probeUsage.getOrDefault(key, 0);
    }

    private static String hostKey(String url) {
        try {
            return normalizeHost(URI.create(url).getHost());
        } catch (RuntimeException e) {
            return "";
        }
    }

    private static String normalizeHost(String host) {
        return host == null ? "" : host.strip().toLowerCase(Locale.ROOT);
    }

    private static String endpointKey(String method, String url) {
        String normalizedMethod = method == null ? "" : method.strip().toUpperCase(Locale.ROOT);
        try {
            URI uri = URI.create(url);
            String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
            String host = normalizeHost(uri.getHost());
            int port = uri.getPort();
            if (port == -1) port = "https".equals(scheme) ? 443 : 80;
            String authority = host + ":" + port;
            String path = uri.getRawPath();
            if (path == null || path.isBlank()) path = "/";
            return normalizedMethod + " " + scheme + "://" + authority + path;
        } catch (RuntimeException e) {
            return normalizedMethod + " " + (url == null ? "" : url);
        }
    }

    boolean start() { return status.compareAndSet(RunStatus.PLANNED, RunStatus.RUNNING); }

    synchronized boolean pause() { return transition(RunStatus.RUNNING, RunStatus.PAUSED); }
    synchronized boolean resume() { return transition(RunStatus.PAUSED, RunStatus.RUNNING); }
    synchronized boolean cancel() { return stop(RunStatus.CANCELLED, ""); }
    synchronized boolean complete() { return stop(RunStatus.COMPLETED, ""); }
    synchronized boolean fail(String reason) { return stop(RunStatus.FAILED, reason); }
    private boolean transition(RunStatus from, RunStatus to) {
        if (!status.compareAndSet(from, to)) return false;
        event("LIFECYCLE", "", "", "", to.name(), false, 0, ""); notifyAll(); return true;
    }
    private boolean stop(RunStatus to, String reason) {
        if (!isActive() && status() != RunStatus.PLANNED) return false;
        status.set(to); finishedAt.set(Instant.now());
        if (to == RunStatus.FAILED) failureReason.set(reason == null ? "" : reason.strip());
        event("LIFECYCLE", "", "", "", to.name(), false, 0, ""); notifyAll(); return true;
    }
    synchronized boolean awaitReady() {
        while (status() == RunStatus.PAUSED) {
            try { wait(); } catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); cancel(); return false; }
        }
        return isRunning() && !Thread.currentThread().isInterrupted();
    }
    boolean isRunning() { return status() == RunStatus.RUNNING; }
    boolean isActive() { return isRunning() || status() == RunStatus.PAUSED; }
    boolean isCancelled() { return status() == RunStatus.CANCELLED; }
    synchronized void parent(String id) { parentId = id == null ? "" : id; }

    synchronized void dispatching(RequestPlan plan) {
        attempts++; dispatched++;
        var request = plan.policyRequest();
        event("DISPATCH", request.probeId(), RunRecord.target(request.method(), request.url()), plan.requestHash(), "IN_FLIGHT", true, 0, "");
    }
    synchronized void record(RequestPlan plan, ActiveRequestGateway.Result result) {
        if (!result.dispatched()) { attempts++; denied++; }
        boolean hasResponse = false;
        try { hasResponse = result.response() != null && result.response().hasResponse() && result.response().response() != null; }
        catch (RuntimeException ignored) { /* An unavailable response is an inconclusive dispatch. */ }
        if (hasResponse) responses++;
        if (result.dispatched() && (result.error() != null || !hasResponse)) errors++;
        if (result.transportElapsedNanos() > 0) transportNanos = saturatedAdd(transportNanos, result.transportElapsedNanos());
        var request = plan == null ? null : plan.policyRequest();
        event("REQUEST", request == null ? "unspecified" : request.probeId(),
                request == null ? "" : RunRecord.target(request.method(), request.url()),
                plan == null ? "" : plan.requestHash(), result.decision().code().name(), result.dispatched(),
                Math.max(0, result.transportElapsedNanos()), hasResponse ? "RESPONSE" : result.dispatched() ? "NO_RESPONSE" : "DENIED");
    }
    synchronized void probe(RunRecord.Probe probe) {
        if (!probes.containsKey(probe.key()) && probes.size() >= RunRecord.MAX_PROBES) { omittedProbes++; return; }
        // A failure in any insertion point keeps the grouped retry eligible.
        var prior = probes.get(probe.key());
        if (prior != null && prior.retryable() && !probe.retryable()) return;
        probes.put(probe.key(), probe);
        event("PROBE", probe.probe(), probe.target(), "", probe.status().name(), false, 0, probe.key());
    }
    synchronized void finding(ReconModel.ActiveRow row) {
        var evidence = row.evidenceRecord();
        finding(new RunRecord.Finding(evidence.id(), RunRecord.findingKey(row), evidence.state()),
                evidence.observation() == null ? "FINDING" : "CALLBACK", evidence.detectorId());
    }
    synchronized void finding(RunRecord.Finding finding, String kind, String detector) {
        if (!findings.containsKey(finding.evidenceId()) && findings.size() >= RunRecord.MAX_FINDINGS) { omittedFindings++; return; }
        findings.put(finding.evidenceId(), finding);
        event(kind, detector, "", "", finding.state().name(), false, 0, finding.evidenceId());
    }
    private void event(String kind, String probe, String target, String hash, String decision, boolean sent, long elapsed, String detail) {
        if (audit.size() == RunRecord.MAX_EVENTS) { audit.removeFirst(); omittedEvents++; }
        audit.add(new RunRecord.Event(UUID.randomUUID().toString(), Instant.now().toString(), kind,
                probe.length() > 128 ? probe.substring(0, 128) : probe, target, hash, decision, sent, elapsed, detail));
    }
    synchronized RunRecord snapshot() {
        // Ledger map keys are hashes in durable history; full URLs and query values are not retained.
        return new RunRecord(id.toString(), parentId, startedAt.toString(), finishedAt() == null ? "" : finishedAt().toString(),
                status(), profile, scope, requestLimits, new RunRecord.Metrics(attempts, requestBudget.used(), dispatched,
                responses, errors, denied, transportNanos, hashed(hostUsage), hashed(endpointUsage), bounded(probeUsage)),
                audit, omittedEvents, List.copyOf(probes.values()), omittedProbes, List.copyOf(findings.values()), omittedFindings);
    }
    private static Map<String, Integer> hashed(Map<String, Integer> values) {
        var result = new HashMap<String, Integer>(); values.forEach((key, value) -> result.put(FindingEvidence.digest(key), value)); return bounded(result);
    }
    private static Map<String, Integer> bounded(Map<String, Integer> values) {
        var out = new java.util.TreeMap<String, Integer>(); int other = 0;
        for (var entry : new java.util.TreeMap<>(values).entrySet()) {
            if (out.size() < 255) out.put(entry.getKey(), entry.getValue()); else other += entry.getValue();
        }
        if (other > 0) out.put(FindingEvidence.digest("omitted quota keys"), other);
        return Map.copyOf(out);
    }
    private static long saturatedAdd(long a, long b) { return a > Long.MAX_VALUE - b ? Long.MAX_VALUE : a + b; }
}
