package com.victor.reconloop;

import java.util.HashMap;
import java.util.Map;

/**
 * Controller-owned run lifetimes. A ticket captures the enable generation at enqueue time:
 * disabling and re-enabling cannot resurrect an old queued job or let it open a fresh run.
 * No monitor is held while a network request is in flight.
 */
final class NativeRunRegistry implements AutoCloseable {
    record Ticket(long generation, long sequence) {}

    private final Map<ScanRun, Ticket> runs = new HashMap<>();
    private boolean enabled;
    private boolean closed;
    private long generation;
    private long sequence;

    NativeRunRegistry(boolean enabled) {
        this.enabled = enabled;
    }

    synchronized Ticket ticket() {
        return new Ticket(generation, ++sequence);
    }

    synchronized boolean isCurrent(Ticket ticket) {
        return ticket != null && !closed && enabled && ticket.generation() == generation;
    }

    synchronized ScanRun begin(Ticket ticket, ScanProfile profile, ScopeSnapshot scope,
                               ScanRun.RequestLimits limits) {
        ScanRun run = ScanRun.begin(profile, scope, limits);
        if (isCurrent(ticket)) runs.put(run, ticket);
        else run.cancel();
        return run;
    }

    synchronized void finish(Ticket ticket) {
        runs.entrySet().removeIf(entry -> {
            if (!entry.getValue().equals(ticket)) return false;
            entry.getKey().complete();
            return true;
        });
    }

    synchronized void setEnabled(boolean value) {
        if (closed || enabled == value) return;
        enabled = value;
        invalidate();
    }

    /** Invalidates work on reset without changing the operator's enabled setting. */
    synchronized void invalidate() {
        generation++;
        runs.keySet().forEach(ScanRun::cancel);
        runs.clear();
    }

    @Override
    public synchronized void close() {
        closed = true;
        enabled = false;
        invalidate();
    }
}
