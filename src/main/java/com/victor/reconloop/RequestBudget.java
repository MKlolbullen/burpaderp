package com.victor.reconloop;

import java.util.concurrent.atomic.AtomicInteger;

/**
 * Hard outbound-request budget.
 *
 * <p>The budget is acquired immediately before a target-directed network send. Unlike checking a
 * stale "remaining" integer before entering a multi-payload probe, {@link #tryAcquire()} is atomic,
 * so concurrent or nested probes cannot overshoot the configured limit.
 */
final class RequestBudget {
    private final int limit;
    private final AtomicInteger used = new AtomicInteger();

    RequestBudget(int limit) {
        this.limit = Math.max(0, limit);
    }

    boolean tryAcquire() {
        while (true) {
            int current = used.get();
            if (current >= limit) return false;
            if (used.compareAndSet(current, current + 1)) return true;
        }
    }

    int limit() {
        return limit;
    }

    int used() {
        return used.get();
    }

    int remaining() {
        return Math.max(0, limit - used());
    }

    boolean exhausted() {
        return remaining() == 0;
    }
}
