package com.victor.reconloop;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;

/**
 * Pure orchestration logic for a multi-agent run over a finding inventory: the round order, the
 * per-role prompts, and the leader's decision (including which of the leader's proposed next actions
 * must clear the {@link ActionGate} before a human touches the target). Dependency-free and directly
 * unit-testable; the live layer (actually calling each provider on the worker pool, then filing the
 * results) is a thin wrapper in the controller.
 *
 * <p>The flow is recon → exploit drafter → adversarial verifier (each a worker round using its role
 * prompt), then the elected leader synthesises everything and emits {@code PROPOSED ACTION:} lines.
 * Every proposed action is classified: passive/drafting proceeds, anything that would touch the
 * target becomes a human-approval escalation.
 */
final class AgentOrchestrator {

    /** One completed round: which role/provider ran and the text it produced. */
    record RoundResult(AgentRole role, LlmProvider provider, String output) {}

    enum OrchestrationDecision { PROCEED, ESCALATE, HOLD }

    /** The whole run: every round, the leader's synthesis, the decision, and any human-approval escalations. */
    record Outcome(List<RoundResult> rounds, String leaderSynthesis,
                   OrchestrationDecision decision, List<String> escalations) {}

    /** Marker the leader is instructed to prefix each concrete next step with, so the gate can classify it. */
    static final String PROPOSED_ACTION_MARKER = "PROPOSED ACTION:";

    private AgentOrchestrator() {}

    // ---- round ordering ----

    /** Fixed execution priority for worker roles; the elected leader always runs last, separately. */
    private static int rolePriority(AgentRole role) {
        return switch (role) {
            case RECON -> 0;
            case EXPLOIT_DRAFTER -> 1;
            case UNCENSORED -> 2;
            case VERIFIER -> 3;   // verifier runs after the drafter/uncensored so it can critique them
            case LEADER -> 4;
        };
    }

    /**
     * The worker rounds to run before the leader: every member except the elected leader, ordered by
     * {@link #rolePriority}. The leader ({@link AgentTeam.Plan#leader()}) is run last by the caller,
     * always with the {@link AgentRole#LEADER} prompt regardless of its nominal role.
     */
    static List<AgentTeam.AgentSpec> workerOrder(AgentTeam.Plan plan) {
        List<AgentTeam.AgentSpec> workers = new ArrayList<>();
        if (plan == null) return workers;
        for (AgentTeam.AgentSpec spec : plan.members()) {
            if (spec == plan.leader()) continue;
            workers.add(spec);
        }
        workers.sort(Comparator.comparingInt(s -> rolePriority(s.role())));
        return workers;
    }

    // ---- per-role prompts ----

    /** The system prompt for a worker/leader round. Every prompt is scoped to authorised assessment only. */
    static String systemPromptFor(AgentRole role) {
        return switch (role) {
            case RECON -> "You are the recon analyst on an AUTHORISED security assessment team. You are given an "
                    + "inventory of findings already discovered on one target. Prioritise: which findings are most "
                    + "worth deeper investigation, and why, citing the specific finding. Be concise. Do not fabricate.";
            case EXPLOIT_DRAFTER -> "You are the exploit reasoner on an AUTHORISED security assessment team. For the "
                    + "most promising findings, draft — ON PAPER ONLY — a proof-of-concept or exploit chain: the "
                    + "primitives, the ordered steps, and the impact. Do NOT execute anything and do NOT instruct "
                    + "anyone to run it now; this is analysis a human will review before any testing.";
            case VERIFIER -> "You are the adversarial verifier on an AUTHORISED security assessment team, and you run "
                    + "on a different model from the drafter on purpose. Attack the drafted proof(s)-of-concept: which "
                    + "assumptions are unproven, which steps would realistically fail, what evidence is missing. Be "
                    + "specific; separate confirmed primitives from assumptions.";
            case UNCENSORED -> "You are the payload specialist on an AUTHORISED security assessment team. Propose "
                    + "candidate payloads/techniques for the drafted proof(s)-of-concept. These are proposals for a "
                    + "human to authorise; do NOT execute anything.";
            case LEADER -> "You are the team leader on an AUTHORISED security assessment. Synthesise the team's "
                    + "analysis into a single ranked assessment of the real, actionable issues, arbitrating any "
                    + "disagreement between the drafter and the verifier. Then, for each concrete next step you "
                    + "recommend, output one line that begins exactly with '" + PROPOSED_ACTION_MARKER + "' followed "
                    + "by the step. Reason only from the evidence given; do not fabricate. Remember that any step "
                    + "that sends traffic to or changes the target must be performed by a human, not by the team.";
        };
    }

    /** Assembles the user prompt for a round: the inventory, plus prior rounds' output for later roles. */
    static String userPromptFor(AgentRole role, String inventory, List<RoundResult> prior) {
        StringBuilder out = new StringBuilder();
        out.append(inventory == null ? "" : inventory);
        if (prior != null && !prior.isEmpty() && role != AgentRole.RECON) {
            out.append("\n\n---\nTEAM ANALYSIS SO FAR:\n");
            for (RoundResult r : prior) {
                out.append("\n[").append(r.role().title()).append(" — ").append(r.provider().label()).append("]\n")
                        .append(r.output() == null ? "" : r.output().strip()).append("\n");
            }
        }
        return out.toString();
    }

    // ---- leader decision + gate ----

    /** Extracts the text of each {@code PROPOSED ACTION:} line from the leader's output (marker stripped). */
    static List<String> extractProposedActions(String leaderOutput) {
        List<String> actions = new ArrayList<>();
        if (leaderOutput == null) return actions;
        for (String rawLine : leaderOutput.split("\n")) {
            String line = rawLine.strip();
            // Tolerate a leading markdown bullet / list marker before the keyword.
            String stripped = line.replaceFirst("^[-*+\\d.)\\s]+", "");
            String candidate = stripped.length() >= line.length() - 4 ? stripped : line;
            int at = indexOfIgnoreCase(candidate, PROPOSED_ACTION_MARKER);
            if (at >= 0) {
                String action = candidate.substring(at + PROPOSED_ACTION_MARKER.length()).strip();
                if (!action.isEmpty()) actions.add(action);
            }
        }
        return actions;
    }

    /**
     * The leader's decision. Every proposed action is run through the {@link ActionGate}; those needing
     * a human become escalations. ESCALATE if any escalation exists, PROCEED if the leader synthesised
     * with no gated action, HOLD when there is no leader synthesis at all.
     */
    static Outcome decide(List<RoundResult> rounds, String leaderOutput) {
        List<RoundResult> safeRounds = rounds == null ? List.of() : List.copyOf(rounds);
        if (leaderOutput == null || leaderOutput.isBlank()) {
            return new Outcome(safeRounds, "", OrchestrationDecision.HOLD, List.of());
        }
        List<String> escalations = new ArrayList<>();
        for (String action : extractProposedActions(leaderOutput)) {
            if (ActionGate.gate(action) == ActionGate.GateDecision.REQUIRES_HUMAN) escalations.add(action);
        }
        OrchestrationDecision decision = escalations.isEmpty()
                ? OrchestrationDecision.PROCEED : OrchestrationDecision.ESCALATE;
        return new Outcome(safeRounds, leaderOutput.strip(), decision, List.copyOf(escalations));
    }

    private static int indexOfIgnoreCase(String haystack, String needle) {
        return haystack.toLowerCase(Locale.ROOT).indexOf(needle.toLowerCase(Locale.ROOT));
    }
}
