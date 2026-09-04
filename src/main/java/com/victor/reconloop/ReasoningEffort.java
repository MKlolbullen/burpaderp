package com.victor.reconloop;

import java.util.Locale;

/**
 * Provider-neutral "how hard should it think" scale for an agent, mapped onto each vendor's own
 * reasoning knob. The scale mirrors Anthropic's effort levels (low → max); other providers expose
 * coarser or differently-shaped controls, so the mappings below deliberately clamp/translate rather
 * than assume a 1:1 correspondence. Pure and dependency-free so it's directly unit-testable.
 *
 * <p>Exact per-vendor field names and value ranges drift over time; the request-building layer that
 * consumes these is the single place to adjust when a provider changes its API.
 */
enum ReasoningEffort {
    /** Low reasoning effort: minimal deliberation, fastest response. */
    LOW,
    /** Medium reasoning effort: balanced deliberation and speed. */
    MEDIUM,
    /** High reasoning effort: thorough analysis, default level. */
    HIGH,
    /** Extra-high reasoning effort: deep deliberation for complex problems. */
    XHIGH,
    /** Maximum reasoning effort: exhaustive analysis, slowest but most thorough. */
    MAX;

    /** Anthropic {@code output_config.effort} value (low|medium|high|xhigh|max). */
    String anthropicEffort() {
        return name().toLowerCase(Locale.ROOT);
    }

    /** OpenAI / xAI style {@code reasoning_effort} — their scale tops out at "high". */
    String openAiReasoningEffort() {
        return switch (this) {
            case LOW -> "low";
            case MEDIUM -> "medium";
            case HIGH, XHIGH, MAX -> "high";
        };
    }

    /** Google Gemini {@code thinkingConfig.thinkingBudget} token hint (larger = more deliberation). */
    int geminiThinkingBudget() {
        return switch (this) {
            case LOW -> 1024;
            case MEDIUM -> 4096;
            case HIGH -> 8192;
            case XHIGH -> 16384;
            case MAX -> 24576;
        };
    }

    /** Case-insensitive parse of a UI label; unknown/blank defaults to {@link #HIGH}. */
    static ReasoningEffort fromLabel(String label) {
        if (label == null || label.isBlank()) return HIGH;
        for (ReasoningEffort effort : values()) {
            if (effort.name().equalsIgnoreCase(label.trim())) return effort;
        }
        return HIGH;
    }
}
