package com.victor.reconloop;

/** Versioned review procedures, injected into role prompts; these grant no execution capabilities. */
enum AgentSkill {
    SURFACE("surface-v1", "Map captured endpoints, parameters, trust boundaries and client-side sources/sinks. Distinguish observed routes from inferred ones; identify missing context."),
    WEB_VULNERABILITIES("web-v1", "Review XSS source-to-sink flow and encoding; CSRF authentication, anti-CSRF tokens, Origin and SameSite assumptions; SSRF URL control and destination validation. Missing headers alone are not vulnerabilities."),
    ACCESS_AND_SECRETS("access-secrets-v1", "Review object/tenant ownership and role boundaries, injection and business logic. Treat redacted credentials as exposure hypotheses, never proof that a key works; require tester-owned accounts for access-control PoCs."),
    MANUAL_POC("poc-v1", "Draft a manual, non-destructive PoC with exact request/code edits, inert markers, prerequisites, expected observations and disproof criteria. Never claim it ran or suggest automatic execution."),
    BOUNDARY_VARIANTS("boundaries-v1", "Consider encoding, parsing, type, origin, redirect and normalization boundaries. Explain which missing checks each inert payload variation would test; do not infer server behavior from a client-only snippet."),
    SKEPTICAL_REVIEW("skeptic-v1", "Challenge every candidate: trace reachability, sanitization, permissions, environmental assumptions and benign explanations. Preserve disagreements; source presence is not exploitability."),
    REPORTING("report-v1", "Prioritize supported hypotheses and unresolved assumptions. Give every candidate a review verdict and a practical manual next step. Retain rejected/uncertain cases and reviewer disagreements; model agreement never upgrades verification state.");

    private final String id, instructions;
    AgentSkill(String id, String instructions) { this.id = id; this.instructions = instructions; }
    String id() { return id; }
    String instructions() { return instructions; }
}
