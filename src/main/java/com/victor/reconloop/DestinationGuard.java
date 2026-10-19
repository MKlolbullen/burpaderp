package com.victor.reconloop;

import java.net.InetAddress;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.*;

/** Resolves once before quota admission; only a validated numeric address escapes to transport. */
final class DestinationGuard {
    @FunctionalInterface interface Resolver { List<String> resolve(String host) throws Exception; }
    record Resolved(String address, String serverName) {}
    static final class Rejected extends Exception {
        final RequestPolicy.DecisionCode code;
        Rejected(RequestPolicy.DecisionCode code, String reason) { super(reason); this.code = code; }
    }
    private static final ThreadPoolExecutor DNS = new ThreadPoolExecutor(0, 4, 30, TimeUnit.SECONDS,
            new SynchronousQueue<>(), task -> { Thread thread = new Thread(task, "Recon-Hound-DNS"); thread.setDaemon(true); return thread; },
            new ThreadPoolExecutor.AbortPolicy());
    private final Resolver resolver;

    DestinationGuard(Resolver resolver) { this.resolver = Objects.requireNonNull(resolver); }

    static DestinationGuard system() {
        return new DestinationGuard(bounded(host -> Arrays.stream(InetAddress.getAllByName(host))
                .map(InetAddress::getHostAddress).toList(), DNS, Duration.ofSeconds(5)));
    }

    static Resolver bounded(Resolver resolver, ExecutorService executor, Duration timeout) {
        return host -> {
            Future<List<String>> task = executor.submit(() -> resolver.resolve(host));
            try { return task.get(timeout.toMillis(), TimeUnit.MILLISECONDS); }
            finally { if (!task.isDone()) task.cancel(true); }
        };
    }

    Resolved resolve(String rawHost) throws Rejected {
        DestinationAddress.Host host = DestinationAddress.inspect(rawHost);
        if (host.kind() == DestinationAddress.Kind.PROTECTED) throw protectedAddress();
        if (host.kind() == DestinationAddress.Kind.INVALID) throw new Rejected(RequestPolicy.DecisionCode.INVALID_REQUEST, "invalid or ambiguous destination");
        if (host.kind() == DestinationAddress.Kind.PUBLIC) return new Resolved(host.canonical(), "");
        List<String> addresses;
        try { addresses = resolver.resolve(host.canonical()); }
        catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new Rejected(RequestPolicy.DecisionCode.DESTINATION_UNAVAILABLE, "destination resolution interrupted");
        } catch (Exception e) {
            throw new Rejected(RequestPolicy.DecisionCode.DESTINATION_UNAVAILABLE, "destination resolution failed, timed out or resolver capacity exhausted");
        }
        if (addresses == null || addresses.isEmpty()) throw new Rejected(RequestPolicy.DecisionCode.DESTINATION_UNAVAILABLE, "destination has no usable addresses");
        String selected = null;
        for (String address : addresses) {
            DestinationAddress.Host candidate = DestinationAddress.inspect(address);
            if (candidate.kind() == DestinationAddress.Kind.PROTECTED) throw protectedAddress();
            if (candidate.kind() != DestinationAddress.Kind.PUBLIC)
                throw new Rejected(RequestPolicy.DecisionCode.DESTINATION_UNAVAILABLE, "resolver returned an invalid numeric address");
            if (selected == null) selected = candidate.canonical();
        }
        return new Resolved(selected, host.canonical());
    }

    private static Rejected protectedAddress() {
        return new Rejected(RequestPolicy.DecisionCode.PROTECTED_DESTINATION, "destination answer contains a protected address");
    }
}
