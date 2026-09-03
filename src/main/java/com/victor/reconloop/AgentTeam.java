package com.victor.reconloop;

import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * Pure roster logic for the multi-agent team: turns a set of configured {@link AgentSpec}s into a
 * {@link Plan} with an elected leader. Dependency-free and directly unit-testable; the live
 * orchestration (actually calling the providers, running the rounds, driving the approval gate) is a
 * separate layer built on top of this.
 */
final class AgentTeam {

    /**
     * One configured team member: its role, the provider/model/key it runs on, how hard it should
     * think ({@link ReasoningEffort}), and its per-run token budget. This is the unit of configuration
     * the operator edits — the richer successor to a bare provider+model+key credential.
     */
    record AgentSpec(AgentRole role, LlmProvider provider, String model, String apiKey,
                     ReasoningEffort effort, int tokenBudget) {

        /** "Most powerful" score used for leader election when no role is explicitly LEADER. */
        long powerScore() {
            ReasoningEffort e = effort == null ? ReasoningEffort.HIGH : effort;
            return (long) e.ordinal() * 1_000_000L + Math.max(0, tokenBudget);
        }

        String resolvedModel() {
            return model == null || model.isBlank() ? provider.defaultModel() : model.trim();
        }
    }

    /** A resolved team: the elected leader (may be null when empty) plus every member, leader included. */
    record Plan(AgentSpec leader, List<AgentSpec> members) {}

    private AgentTeam() {}

    /**
     * Elects the leader: an explicitly {@link AgentRole#LEADER}-roled member wins (the first one, in
     * configuration order); otherwise the "most powerful" member by the effort/budget the operator
     * configured — their own signal for who should think hardest — with ties broken by configuration
     * order. Empty input yields no leader.
     */
    static Optional<AgentSpec> electLeader(List<AgentSpec> specs) {
        if (specs == null || specs.isEmpty()) return Optional.empty();
        for (AgentSpec spec : specs) {
            if (spec.role() == AgentRole.LEADER) return Optional.of(spec);
        }
        AgentSpec best = null;
        for (AgentSpec spec : specs) {
            if (best == null || spec.powerScore() > best.powerScore()) best = spec;
        }
        return Optional.ofNullable(best);
    }

    /** Builds a plan from the enabled specs, electing a leader. Members preserve configuration order. */
    static Plan plan(List<AgentSpec> specs) {
        List<AgentSpec> members = specs == null ? List.of() : List.copyOf(specs);
        return new Plan(electLeader(members).orElse(null), members);
    }

    /** True if any enabled member holds a sensitive role, i.e. the run may produce gate-controlled output. */
    static boolean hasSensitiveMember(Plan plan) {
        if (plan == null) return false;
        return plan.members().stream().anyMatch(spec -> spec.role().sensitive());
    }

    /** Human-readable, one-line-per-member roster summary for the UI / logs; the leader is starred. */
    static String describe(Plan plan) {
        if (plan == null || plan.members().isEmpty()) return "No agents enabled.";
        StringBuilder out = new StringBuilder();
        for (AgentSpec spec : plan.members()) {
            boolean isLeader = spec == plan.leader();
            ReasoningEffort effort = spec.effort() == null ? ReasoningEffort.HIGH : spec.effort();
            out.append(isLeader ? "★ " : "  ")
                    .append(spec.role().title())
                    .append(" — ").append(spec.provider().label())
                    .append(" / ").append(spec.resolvedModel())
                    .append(" (effort ").append(effort.name().toLowerCase(Locale.ROOT))
                    .append(", budget ").append(spec.tokenBudget()).append(")")
                    .append('\n');
        }
        out.append(plan.leader() != null
                ? "Leader makes the final call; any active/PoC step escalates to a human."
                : "No leader elected.");
        return out.toString();
    }
}
