package com.victor.reconloop;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Pure model and accounting for the agent-team activity view: one {@link RunEntry} per round, a rough
 * per-round token estimate, and a per-provider usage rollup for the activity page's usage meter.
 * Dependency-free and directly unit-testable; the Swing table and the live wiring live elsewhere.
 *
 * <p>Token counts are <em>estimated</em> from text length — the raw-HTTP LLM client does not parse
 * per-provider billed-usage fields — so everything here is labelled as an estimate, never billed cost.
 */
final class AgentActivity {

    /** One completed round as shown on the activity page. */
    record RunEntry(AgentRole role, LlmProvider provider, String model, String status,
                    long estInputTokens, long estOutputTokens, String summary) {}

    /** The end-of-run summary: the leader's decision, synthesis, escalations, and a usage line. */
    record RunSummary(String decision, String synthesis, List<String> escalations, String usageText) {}

    /** Rough token estimate for a piece of text (~4 characters per token); {@code null}/blank is 0. */
    static long estimateTokens(String text) {
        if (text == null) return 0;
        int len = text.strip().length();
        return len == 0 ? 0 : (len + 3) / 4;
    }

    /** Per-provider usage rollup across a run's entries. */
    record ProviderUsage(LlmProvider provider, int calls, long inputTokens, long outputTokens) {
        long totalTokens() { return inputTokens + outputTokens; }
    }

    /** Aggregates entries by provider, preserving first-seen order. */
    static List<ProviderUsage> aggregate(List<RunEntry> entries) {
        Map<LlmProvider, long[]> acc = new LinkedHashMap<>(); // provider -> [calls, in, out]
        if (entries != null) {
            for (RunEntry e : entries) {
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

    /** One-line human-readable usage summary; explicitly an estimate, since no billed usage is parsed. */
    static String formatUsage(List<RunEntry> entries) {
        List<ProviderUsage> usage = aggregate(entries);
        if (usage.isEmpty()) return "No LLM calls yet.";
        long totalCalls = 0, totalTokens = 0;
        for (ProviderUsage u : usage) { totalCalls += u.calls(); totalTokens += u.totalTokens(); }
        StringBuilder sb = new StringBuilder();
        sb.append("Estimated usage — ~").append(totalTokens).append(" tokens across ")
                .append(totalCalls).append(" call(s):");
        for (int i = 0; i < usage.size(); i++) {
            ProviderUsage u = usage.get(i);
            sb.append(i == 0 ? " " : ", ").append(u.provider().label())
                    .append(" ~").append(u.totalTokens()).append(" (").append(u.calls()).append(')');
        }
        sb.append(". Estimated from text length, not billed usage.");
        return sb.toString();
    }

    private AgentActivity() {}
}
