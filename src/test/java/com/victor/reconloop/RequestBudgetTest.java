package com.victor.reconloop;

import org.junit.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.*;

public class RequestBudgetTest {

    @Test
    public void neverExceedsLimitSequentially() {
        RequestBudget budget = new RequestBudget(3);

        assertTrue(budget.tryAcquire());
        assertTrue(budget.tryAcquire());
        assertTrue(budget.tryAcquire());
        assertFalse(budget.tryAcquire());
        assertFalse(budget.tryAcquire());

        assertEquals(3, budget.used());
        assertEquals(0, budget.remaining());
        assertTrue(budget.exhausted());
    }

    @Test
    public void clampsNegativeLimitToZero() {
        RequestBudget budget = new RequestBudget(-10);
        assertEquals(0, budget.limit());
        assertFalse(budget.tryAcquire());
        assertEquals(0, budget.used());
    }

    @Test
    public void acquisitionIsAtomicAcrossThreads() throws Exception {
        int limit = 73;
        int workers = 12;
        int attemptsPerWorker = 50;
        RequestBudget budget = new RequestBudget(limit);
        ExecutorService pool = Executors.newFixedThreadPool(workers);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger acquired = new AtomicInteger();
        List<Runnable> tasks = new ArrayList<>();

        for (int i = 0; i < workers; i++) {
            tasks.add(() -> {
                try {
                    start.await();
                    for (int j = 0; j < attemptsPerWorker; j++) {
                        if (budget.tryAcquire()) acquired.incrementAndGet();
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }

        tasks.forEach(pool::submit);
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(5, TimeUnit.SECONDS));

        assertEquals(limit, acquired.get());
        assertEquals(limit, budget.used());
        assertEquals(0, budget.remaining());
    }
}
