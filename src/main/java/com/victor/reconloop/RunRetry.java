package com.victor.reconloop;

import burp.api.montoya.http.message.requests.HttpRequest;
import java.util.*;
import java.util.function.BiConsumer;
import java.util.function.Predicate;

/** Rebuilds eligible probes from current site-map messages; persisted bytes are never replayed. */
final class RunRetry {
    record Target(HttpRequest request, List<RunRecord.Probe> probes) {}
    record Plan(String parentId, List<Target> targets, int unavailable) {
        ScopeSnapshot scope() { return ScopeSnapshot.forTargets(targets.stream().map(t -> t.request().url()).toList()); }
    }
    static Plan plan(String parentId, List<RunRecord.Probe> probes, List<HttpRequest> current, Predicate<String> scope) {
        Map<String, HttpRequest> requests = new LinkedHashMap<>();
        for (var request : current) {
            if (request == null) continue;
            try { if (scope.test(request.url())) requests.put(RunRecord.target(request.method(), request.url()), request); }
            catch (RuntimeException denied) { /* Missing current scope is not recoverable from history. */ }
        }
        Map<String, List<RunRecord.Probe>> groups = new LinkedHashMap<>(); int unavailable = 0;
        for (var probe : probes) {
            if (!probe.retryable() || !Set.of("NATIVE_ACTIVE", "CORPUS").contains(probe.source())) continue;
            if (!requests.containsKey(probe.target())) { unavailable++; continue; }
            groups.computeIfAbsent(probe.target(), key -> new ArrayList<>()).add(probe);
        }
        return new Plan(parentId, groups.entrySet().stream().map(e -> new Target(requests.get(e.getKey()), List.copyOf(e.getValue()))).toList(), unavailable);
    }
    static void execute(Plan plan, ScanRun run, ActiveRequestGateway gateway, ActiveTestEngine active, CorpusFuzzEngine corpus,
                        BiConsumer<ActiveTestEngine.ActiveFinding, HttpRequest> findings) {
        for (var target : plan.targets()) {
            if (!run.awaitReady() || run.requestBudget().exhausted()) break;
            var nativeKeys = new HashSet<String>(); var corpusKeys = new HashSet<String>();
            var encodings = EnumSet.noneOf(PayloadEncoder.Encoding.class); int localLimit = 0;
            for (var probe : target.probes()) {
                if (probe.source().equals("NATIVE_ACTIVE")) nativeKeys.add(probe.key());
                else {
                    try { encodings.add(PayloadEncoder.Encoding.valueOf(probe.encoding())); }
                    catch (IllegalArgumentException invalid) { continue; }
                    corpusKeys.add(probe.key()); localLimit = Math.max(localLimit, probe.localLimit());
                }
            }
            if (!nativeKeys.isEmpty()) for (var finding : active.test(target.request(), run, gateway, nativeKeys)) findings.accept(finding, target.request());
            if (!corpusKeys.isEmpty()) for (var parameter : target.request().parameters()) {
                if (parameter == null || "COOKIE".equalsIgnoreCase(String.valueOf(parameter.type()))) continue;
                for (var finding : corpus.fuzz(target.request(), parameter, encodings, localLimit, run, gateway, corpusKeys)) findings.accept(finding, target.request());
            }
        }
    }
}
