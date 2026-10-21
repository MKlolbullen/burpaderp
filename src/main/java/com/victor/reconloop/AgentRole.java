package com.victor.reconloop;

/**
 * The five roles in the review team. Provider defaults are editable presets, not quality rankings.
 * Each role has a {@code sensitive} flag: sensitive roles produce content —
 * proof-of-concept exploits, offensive payloads — that must clear the {@link ActionGate}'s
 * human-approval step before it is ever used against a target. Assignments are defaults only; the
 * operator can reassign any provider to any role.
 */
enum AgentRole {

    /** Leader role: synthesizes team opinions, arbitrates disagreement, and owns final decisions. */
    LEADER("Lead reporter",
            "Synthesises the team's opinions, arbitrates disagreement, and owns the final assessment "
                    + "and every escalation to a human.",
            LlmProvider.ANTHROPIC, false),

    /** Recon role: fast first-pass triage over large inputs to surface candidate issues. */
    RECON("Surface analyst",
            "Fast, cheap first-pass triage over large inputs (JavaScript, traffic); surfaces candidate "
                    + "issues for the rest of the team.",
            LlmProvider.GEMINI, false),

    /** Exploit drafter role: drafts proof-of-concept exploits on paper and reasons about exploitability. */
    EXPLOIT_DRAFTER("Vulnerability / PoC analyst",
            "Drafts a proof-of-concept on paper and reasons about exploitability; never executes "
                    + "anything itself.",
            LlmProvider.OPENAI, true),

    /** Verifier role: adversarially checks the drafter's work using a different LLM provider. */
    VERIFIER("Skeptical reviewer",
            "A different provider from the drafter, tasked with breaking the drafted PoC's assumptions "
                    + "(cross-model check).",
            LlmProvider.XAI, false),

    /** Payload / boundary specialist: designs variations and examines parsing/trust boundaries. */
    PAYLOAD_SPECIALIST("Payload / boundary specialist",
            "Designs inert payload variations and boundary tests for candidate weaknesses; "
                    + "active verification requires an explicit governed request plan.",
            LlmProvider.VENICE, true);

    private final String title;
    private final String mission;
    private final LlmProvider defaultProvider;
    private final boolean sensitive;

    /**
     * Constructs an agent role with its display properties and default provider.
     *
     * @param title the human-readable role title
     * @param mission the role's purpose and responsibilities
     * @param defaultProvider the default provider preset for this role
     * @param sensitive whether this role produces content requiring human approval
     */
    AgentRole(String title, String mission, LlmProvider defaultProvider, boolean sensitive) {
        this.title = title;
        this.mission = mission;
        this.defaultProvider = defaultProvider;
        this.sensitive = sensitive;
    }

    /**
     * Returns the human-readable title for this role.
     *
     * @return the role title
     */
    String title() { return title; }

    /**
     * Returns the mission statement describing this role's purpose.
     *
     * @return the mission description
     */
    String mission() { return mission; }

    /**
     * Returns the default LLM provider for this role.
     *
     * @return the default provider
     */
    LlmProvider defaultProvider() { return defaultProvider; }

    /** Sensitive roles emit PoCs / offensive payloads that must pass the human-approval gate before use. */
    boolean sensitive() { return sensitive; }

    /** The role this provider is the configured default for, or {@link #RECON} as a safe generic fallback. */
    static AgentRole defaultRoleFor(LlmProvider provider) {
        for (AgentRole role : values()) {
            if (role.defaultProvider == provider) return role;
        }
        return RECON;
    }
}
