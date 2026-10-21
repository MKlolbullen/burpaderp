package com.victor.reconloop;

import java.util.ArrayList;
import java.util.List;
import java.util.Queue;
import java.util.concurrent.*;

final class ManualExecutor extends AbstractExecutorService {
    private final Queue<Runnable> tasks = new ConcurrentLinkedQueue<>();
    private volatile boolean stopped;
    @Override public void execute(Runnable task) {
        if (stopped) throw new RejectedExecutionException();
        tasks.add(task);
    }
    void runAll() throws Exception {
        Runnable task;
        while ((task = tasks.poll()) != null) {
            task.run();
            if (task instanceof Future<?> future) future.get(); // Surface swallowed worker failures.
        }
    }
    @Override public void shutdown() { stopped = true; }
    @Override public List<Runnable> shutdownNow() {
        stopped = true; List<Runnable> result = new ArrayList<>(tasks); tasks.clear(); return result;
    }
    @Override public boolean isShutdown() { return stopped; }
    @Override public boolean isTerminated() { return stopped && tasks.isEmpty(); }
    @Override public boolean awaitTermination(long timeout, TimeUnit unit) { return isTerminated(); }
}
