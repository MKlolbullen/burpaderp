package com.victor.reconloop;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Run-scoped ownership for request accounting and cooperative cancellation.
 *
 * <p>The contained {@link RequestBudget} is the global cap for the run.  A gateway acquires a token
 * immediately before dispatching an outbound request, so concurrent probes cannot overshoot it.
 */
final class ScanRun {
    private final UUID id;
    private final Instant startedAt;
    private final ScanProfile profile;
    private final ScopeSnapshot scope;
    private final RequestBudget requestBudget;
    private final AtomicReference<RunStatus> status = new AtomicReference<>(RunStatus.PLANNED);
    private final AtomicReference<Instant> finishedAt = new AtomicReference<>();
    private final AtomicReference<String> failureReason = new AtomicReference<>();

    private ScanRun(UUID id, Instant startedAt, ScanProfile profile, ScopeSnapshot scope, int requestLimit) {
        this.id = Objects.requireNonNull(id, "id");
        this.startedAt = Objects.requireNonNull(startedAt, "startedAt");
        this.profile = Objects.requireNonNull(profile, "profile");
        this.scope = Objects.requireNonNull(scope, "scope");
        this.requestBudget = new RequestBudget(requestLimit);
    }

    static ScanRun begin(ScanProfile profile, ScopeSnapshot scope, int requestLimit) {
        ScanRun run = new ScanRun(UUID.randomUUID(), Instant.now(), profile,
                scope == null ? ScopeSnapshot.empty() : scope, requestLimit);
        run.start();
        return run;
    }

    UUID id() { return id; }
    Instant startedAt() { return startedAt; }
    ScanProfile profile() { return profile; }
    ScopeSnapshot scope() { return scope; }
    RequestBudget requestBudget() { return requestBudget; }
    RunStatus status() { return status.get(); }
    Instant finishedAt() { return finishedAt.get(); }
    String failureReason() { return failureReason.get(); }

    boolean start() {
        return status.compareAndSet(RunStatus.PLANNED, RunStatus.RUNNING);
    }

    boolean cancel() {
        while (true) {
            RunStatus current = status.get();
            if (current == RunStatus.CANCELLED || current == RunStatus.COMPLETED || current == RunStatus.FAILED) return false;
            if (status.compareAndSet(current, RunStatus.CANCELLED)) {
                finishedAt.compareAndSet(null, Instant.now());
                return true;
            }
        }
    }

    boolean complete() {
        if (!status.compareAndSet(RunStatus.RUNNING, RunStatus.COMPLETED)) return false;
        finishedAt.compareAndSet(null, Instant.now());
        return true;
    }

    boolean fail(String reason) {
        while (true) {
            RunStatus current = status.get();
            if (current == RunStatus.CANCELLED || current == RunStatus.COMPLETED || current == RunStatus.FAILED) return false;
            if (status.compareAndSet(current, RunStatus.FAILED)) {
                failureReason.set(reason == null ? "" : reason.strip());
                finishedAt.compareAndSet(null, Instant.now());
                return true;
            }
        }
    }

    boolean isRunning() { return status() == RunStatus.RUNNING; }
    boolean isCancelled() { return status() == RunStatus.CANCELLED; }
}
