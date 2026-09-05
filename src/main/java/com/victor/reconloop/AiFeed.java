package com.victor.reconloop;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.LongSupplier;

/**
 * Pure, dependency-free model and capped in-memory store for the global <em>AI feed</em>: a single
 * stream of every LLM touchpoint in the extension — false-positive triage, JavaScript review, exploit
 * chaining, Nuclei-template authoring, multi-agent rounds, and the human-approval gate decisions that
 * govern them. The Swing table and the live wiring live elsewhere; everything here is directly
 * unit-testable.
 *
 * <p><b>In-memory only, never persisted.</b> LLM prompts and responses can carry target data, payloads,
 * and secrets seen in traffic, so the feed follows the extension's stance that keys and LLM traffic
 * never touch disk or the proxy history — it is a session-lived, capped ring, not a log file.
 *
 * <p>Token counts are <em>estimated</em> from text length (via {@link AgentActivity#estimateTokens});
 * the raw-HTTP LLM client parses no billed-usage fields, so counts are labelled as estimates, never cost.
 */
final class AiFeed {

    /** What kind of AI activity an event records. */
    enum Kind {
        TRIAGE("Triage"),
        JS_REVIEW("JS review"),
        CHAIN_ANALYSIS("Chain analysis"),
        NUCLEI_TEMPLATE("Nuclei template"),
        AGENT_ROUND("Agent round"),
        GATE_DECISION("Gate decision"),
        ESCALATION("Escalation");

        private final String label;
        Kind(String label) { this.label = label; }
        String label() { return label; }
    }

    /** How an event turned out. {@code HELD} marks an action the human-approval gate withheld. */
    enum Outcome {
        OK("ok"),
        ERROR("error"),
        HELD("held for human"),
        INFO("info");

        private final String label;
        Outcome(String label) { this.label = label; }
        String label() { return label; }
    }

    /**
     * One activity event. {@code provider}/{@code model} are {@code null} for events computed locally
     * rather than by an LLM call (a gate decision, an escalation). {@code seq} is a monotonic id the
     * {@link Store} assigns; {@code epochMillis} is the store clock's timestamp at record time.
     */
    record Event(long seq, long epochMillis, Kind kind, LlmProvider provider, String model,
                 Outcome outcome, long estInputTokens, long estOutputTokens, String title, String detail) {}

    /** Maps an {@link LlmClient} text result to an outcome: the failure sentinels read as ERROR, else OK. */
    static Outcome outcomeFor(String llmOutput) {
        if (llmOutput == null) return Outcome.ERROR;
        return (llmOutput.startsWith("[error]") || llmOutput.startsWith("[HTTP ") || llmOutput.startsWith("[warning]"))
                ? Outcome.ERROR : Outcome.OK;
    }

    /**
     * Capped, insertion-ordered event store — a fixed-size ring: once full, recording a new event evicts
     * the oldest. Not thread-safe by design: the controller marshals every write and read onto the EDT
     * (where the feed table also lives), so the store is single-thread-confined and needs no locking.
     */
    static final class Store {
        static final int DEFAULT_CAP = 500;

        private final int cap;
        private final LongSupplier clock;
        private final Deque<Event> events = new ArrayDeque<>();
        private long seq;

        Store() { this(DEFAULT_CAP, System::currentTimeMillis); }

        Store(int cap, LongSupplier clock) {
            this.cap = Math.max(1, cap);
            this.clock = clock == null ? System::currentTimeMillis : clock;
        }

        /** Records an event (next {@code seq}, current clock time), evicting the oldest when over cap. */
        Event record(Kind kind, LlmProvider provider, String model, Outcome outcome,
                     long estIn, long estOut, String title, String detail) {
            Event e = new Event(++seq, clock.getAsLong(), kind, provider, model,
                    outcome == null ? Outcome.INFO : outcome,
                    Math.max(0, estIn), Math.max(0, estOut),
                    title == null ? "" : title, detail == null ? "" : detail);
            events.addLast(e);
            while (events.size() > cap) events.removeFirst();
            return e;
        }

        /** All retained events, oldest-first. */
        List<Event> snapshot() { return new ArrayList<>(events); }
        int size() { return events.size(); }
        void clear() { events.clear(); }
    }

    /** Per-provider usage rollup across a set of events, counting only events that carry a provider. */
    record ProviderUsage(LlmProvider provider, int calls, long inputTokens, long outputTokens) {
        long totalTokens() { return inputTokens + outputTokens; }
    }

    /** Aggregates events by provider, preserving first-seen order; events with no provider are skipped. */
    static List<ProviderUsage> aggregate(List<Event> events) {
        Map<LlmProvider, long[]> acc = new LinkedHashMap<>(); // provider -> [calls, in, out]
        if (events != null) {
            for (Event e : events) {
                if (e == null || e.provider() == null) continue;
                long[] a = acc.computeIfAbsent(e.provider(), p -> new long[3]);
                a[0] += 1;
                a[1] += Math.max(0, e.estInputTokens());
                a[2] += Math.max(0, e.estOutputTokens());
            }
        }
        List<ProviderUsage> out = new ArrayList<>();
        for (Map.Entry<LlmProvider, long[]> en : acc.entrySet()) {
            long[] a = en.getValue();
            out.add(new ProviderUsage(en.getKey(), (int) a[0], a[1], a[2]));
        }
        return out;
    }

    /**
     * One-line, feed-wide summary for the activity meter: event count, total estimated tokens, a
     * by-kind breakdown, and a by-provider token breakdown, closing with the estimate disclaimer.
     */
    static String summarize(List<Event> events) {
        if (events == null || events.isEmpty()) return "No AI activity yet.";

        Map<Kind, Integer> byKind = new LinkedHashMap<>();
        long totalTokens = 0;
        for (Event e : events) {
            if (e == null) continue;
            byKind.merge(e.kind(), 1, Integer::sum);
            totalTokens += Math.max(0, e.estInputTokens()) + Math.max(0, e.estOutputTokens());
        }

        StringBuilder sb = new StringBuilder();
        sb.append("AI activity — ").append(events.size()).append(" event(s), ~")
                .append(totalTokens).append(" est tokens.");

        if (!byKind.isEmpty()) {
            sb.append(" By kind:");
            boolean first = true;
            for (Map.Entry<Kind, Integer> en : byKind.entrySet()) {
                sb.append(first ? " " : ", ").append(en.getKey().label()).append(' ').append(en.getValue());
                first = false;
            }
            sb.append('.');
        }

        List<ProviderUsage> usage = aggregate(events);
        if (!usage.isEmpty()) {
            sb.append(" By provider:");
            for (int i = 0; i < usage.size(); i++) {
                ProviderUsage u = usage.get(i);
                sb.append(i == 0 ? " " : ", ").append(u.provider().label())
                        .append(" ~").append(u.totalTokens()).append(" (").append(u.calls()).append(')');
            }
            sb.append('.');
        }

        sb.append(" Estimated from text length, not billed usage.");
        return sb.toString();
    }

    private AiFeed() {}
}
