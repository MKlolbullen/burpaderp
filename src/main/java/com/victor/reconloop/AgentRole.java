package com.victor.reconloop;

/**
 * The roles in the multi-agent "cyber team". Each role has a default provider affinity (the vendor
 * whose strengths best fit it) and a {@code sensitive} flag: sensitive roles produce content —
 * proof-of-concept exploits, offensive payloads — that must clear the {@link ActionGate}'s
 * human-approval step before it is ever used against a target. Assignments are defaults only; the
 * operator can reassign any provider to any role.
 */
enum AgentRole {

    LEADER("Leader / final call",
            "Synthesises the team's opinions, arbitrates disagreement, and owns the final go/no-go "
                    + "and every escalation to a human.",
            LlmProvider.ANTHROPIC, false),

    RECON("Recon / breadth",
            "Fast, cheap first-pass triage over large inputs (JavaScript, traffic); surfaces candidate "
                    + "issues for the rest of the team.",
            LlmProvider.GEMINI, false),

    EXPLOIT_DRAFTER("Exploit reasoner",
            "Drafts a proof-of-concept on paper and reasons about exploitability; never executes "
                    + "anything itself.",
            LlmProvider.OPENAI, true),

    VERIFIER("Adversarial verifier",
            "A different provider from the drafter, tasked with breaking the drafted PoC's assumptions "
                    + "(cross-model check).",
            LlmProvider.XAI, false),

    UNCENSORED("Uncensored specialist",
            "Generates offensive payloads/content that mainstream models over-refuse; always the "
                    + "hardest-gated behind human approval.",
            LlmProvider.VENICE, true);

    private final String title;
    private final String mission;
    private final LlmProvider defaultProvider;
    private final boolean sensitive;

    AgentRole(String title, String mission, LlmProvider defaultProvider, boolean sensitive) {
        this.title = title;
        this.mission = mission;
        this.defaultProvider = defaultProvider;
        this.sensitive = sensitive;
    }

    String title() { return title; }
    String mission() { return mission; }
    LlmProvider defaultProvider() { return defaultProvider; }

    /** Sensitive roles emit PoCs / offensive payloads that must pass the human-approval gate before use. */
    boolean sensitive() { return sensitive; }

    /** The role this provider is the natural default for, or {@link #RECON} as a safe generic fallback. */
    static AgentRole defaultRoleFor(LlmProvider provider) {
        for (AgentRole role : values()) {
            if (role.defaultProvider == provider) return role;
        }
        return RECON;
    }
}
