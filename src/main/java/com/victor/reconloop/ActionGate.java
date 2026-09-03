package com.victor.reconloop;

import java.util.Locale;

/**
 * The human-in-the-loop safety gate for agent-proposed actions. Reasoning and drafting are
 * auto-approved; anything that would put packets on the wire, recreate/execute a vulnerability, or
 * change state on the target always requires an explicit human decision. This encodes the operator's
 * rule that the team must apply "careful consideration before recreating a vulnerability to build a
 * PoC" — drafting a PoC on paper is fine, executing one is not, without a human saying so.
 *
 * <p>Pure and dependency-free so it's directly unit-testable. Classification fails closed: anything it
 * can't confidently place is treated as requiring a human.
 */
final class ActionGate {

    /** A proposed agent action, coarsely classified by risk. */
    enum ActionKind { PASSIVE_ANALYSIS, DRAFT_POC, ACTIVE_PROBE, EXECUTE_POC, DESTRUCTIVE, UNKNOWN }

    /** The gate's ruling: whether an action may proceed automatically or requires explicit human approval. */
    enum GateDecision { AUTO_APPROVED, REQUIRES_HUMAN }

    private ActionGate() {}

    /**
     * Only reading/reasoning is auto-approved: passive analysis and drafting a PoC "on paper".
     * Active probing, recreating/executing a vulnerability, and state-changing (destructive) actions
     * always require a human. Unknown fails closed to {@link GateDecision#REQUIRES_HUMAN}.
     */
    static GateDecision decisionFor(ActionKind kind) {
        return switch (kind) {
            case PASSIVE_ANALYSIS, DRAFT_POC -> GateDecision.AUTO_APPROVED;
            case ACTIVE_PROBE, EXECUTE_POC, DESTRUCTIVE, UNKNOWN -> GateDecision.REQUIRES_HUMAN;
        };
    }

    /**
     * Returns true if the given action kind requires human approval before execution.
     *
     * @param kind the action kind to check
     * @return true if human approval is required, false otherwise
     */
    static boolean requiresHuman(ActionKind kind) {
        return decisionFor(kind) == GateDecision.REQUIRES_HUMAN;
    }

    /**
     * Best-effort keyword classification of a free-text proposed action. Precedence is risk-descending
     * on purpose: if a description mixes signals (e.g. "draft a request and send it"), the higher-risk
     * interpretation wins so the gate errs toward asking a human. Unknown fails closed.
     */
    static ActionKind classify(String description) {
        if (description == null || description.isBlank()) return ActionKind.UNKNOWN;
        String d = description.toLowerCase(Locale.ROOT);

        if (containsAny(d, "delete", "drop table", "rm -rf", "wipe", "overwrite", "destroy",
                "shutdown", "encrypt the", "ransom", "format ", "truncate ")) {
            return ActionKind.DESTRUCTIVE;
        }
        if (containsAny(d, "execute", "recreate", "reproduce the vuln", "reproduce the vulnerability",
                "fire the payload", "run the exploit", "exploit the", "pop a shell", "trigger the vuln",
                "launch the attack", "deliver the payload")) {
            return ActionKind.EXECUTE_POC;
        }
        if (containsAny(d, "send request", "send a request", "send the request", "probe", "scan ",
                "fuzz", "inject", "brute", "sqlmap", "spray", "active test", "replay the request")) {
            return ActionKind.ACTIVE_PROBE;
        }
        if (containsAny(d, "draft", "write a poc", "write a proof", "proof-of-concept", "proof of concept",
                "outline the", "describe how", "sketch the", "on paper")) {
            return ActionKind.DRAFT_POC;
        }
        if (containsAny(d, "analyse", "analyze", "review", "identify", "summarise", "summarize",
                "assess", "explain", "inspect", "read the")) {
            return ActionKind.PASSIVE_ANALYSIS;
        }
        return ActionKind.UNKNOWN;
    }

    /** Convenience: classify a free-text action and return the gate decision in one call. */
    static GateDecision gate(String description) {
        return decisionFor(classify(description));
    }

    private static boolean containsAny(String haystack, String... needles) {
        for (String needle : needles) {
            if (haystack.contains(needle)) return true;
        }
        return false;
    }
}
