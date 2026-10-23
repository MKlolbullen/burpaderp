package com.victor.reconloop;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/** Owns live controls, bounded history, comparisons and retry selection outside ReconController. */
final class RunHistory {
    private record Entry(ScanRun live, RunRecord saved) {
        RunRecord snapshot() { return live == null ? saved : live.snapshot(); }
    }
    record Diff(Set<String> added, Set<String> shared, Set<String> notObserved, boolean complete) {}
    private final Map<String, Entry> entries = new ConcurrentHashMap<>();

    synchronized void register(ScanRun run) {
        while (entries.size() >= RunRecord.MAX_RUNS) {
            var oldest = entries.values().stream().filter(e -> e.live() == null || !e.live().isActive())
                    .min(Comparator.comparing(e -> e.snapshot().startedAt())).orElse(null);
            if (oldest == null) { run.cancel(); return; }
            entries.remove(oldest.snapshot().id());
        }
        entries.put(run.id().toString(), new Entry(run, null));
    }
    synchronized void restore(List<RunRecord> records) {
        entries.clear();
        for (var record : records) entries.put(record.id(), new Entry(null, record.interrupted()));
    }
    synchronized void clear() { entries.values().forEach(e -> { if (e.live() != null) e.live().cancel(); }); entries.clear(); }
    List<RunRecord> snapshot() {
        return entries.values().stream().map(Entry::snapshot).sorted(Comparator.comparing(RunRecord::startedAt).reversed()).toList();
    }
    RunRecord get(String id) { Entry entry = entries.get(id); return entry == null ? null : entry.snapshot(); }
    boolean control(String id, String action) {
        Entry entry = entries.get(id);
        if (entry == null || entry.live() == null) return false;
        return switch (action) {
            case "pause" -> entry.live().pause();
            case "resume" -> entry.live().resume();
            case "cancel" -> entry.live().cancel();
            default -> false;
        };
    }
    void finding(ReconModel.ActiveRow row) {
        var evidence = row.evidenceRecord();
        finding(evidence.runId(), new RunRecord.Finding(evidence.id(), RunRecord.findingKey(row), evidence.state()),
                evidence.observation() == null ? "FINDING" : "CALLBACK", evidence.detectorId());
    }
    void finding(ReconModel.FindingRow row) { finding(row.runId(), RunRecord.passiveFinding(row), "FINDING", "passive"); }
    private void finding(String runId, RunRecord.Finding finding, String kind, String detector) {
        if (runId == null || runId.isEmpty()) return;
        entries.computeIfPresent(runId, (id, entry) -> {
            if (entry.live() != null) { entry.live().finding(finding, kind, detector); return entry; }
            return new Entry(null, entry.saved().withFinding(finding, kind, detector));
        });
    }
    Diff diff(String baseline, String current) {
        RunRecord old = get(baseline), next = get(current);
        if (old == null || next == null) return new Diff(Set.of(), Set.of(), Set.of(), false);
        Set<String> added = new HashSet<>(next.findingKeys()), shared = new HashSet<>(added), missing = new HashSet<>(old.findingKeys());
        added.removeAll(old.findingKeys()); shared.retainAll(old.findingKeys()); missing.removeAll(next.findingKeys());
        return new Diff(Set.copyOf(added), Set.copyOf(shared), Set.copyOf(missing), old.omittedFindings() == 0 && next.omittedFindings() == 0);
    }
    List<RunRecord.Probe> retries(String id) {
        RunRecord run = get(id);
        if (run == null || run.status() == RunStatus.RUNNING || run.status() == RunStatus.PAUSED) return List.of();
        return run.probes().stream().filter(RunRecord.Probe::retryable)
                .filter(p -> Set.of("NATIVE_ACTIVE", "CORPUS").contains(p.source())).toList();
    }
}
