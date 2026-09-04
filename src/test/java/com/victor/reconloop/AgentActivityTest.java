package com.victor.reconloop;

import org.junit.Test;

import java.util.List;

import static org.junit.Assert.*;

public class AgentActivityTest {

    private static AgentActivity.RunEntry entry(LlmProvider provider, long in, long out) {
        return new AgentActivity.RunEntry(AgentRole.RECON, provider, provider.defaultModel(), "ok", in, out, "summary");
    }

    // ---- estimateTokens ----

    @Test
    public void estimateTokensIsZeroForNullOrBlank() {
        assertEquals(0, AgentActivity.estimateTokens(null));
        assertEquals(0, AgentActivity.estimateTokens(""));
        assertEquals(0, AgentActivity.estimateTokens("    \n  "));
    }

    @Test
    public void estimateTokensIsRoughlyOnePerFourChars() {
        assertEquals(1, AgentActivity.estimateTokens("abcd"));       // 4 -> 1
        assertEquals(2, AgentActivity.estimateTokens("abcde"));      // 5 -> ceil(5/4) = 2
        assertEquals(25, AgentActivity.estimateTokens("x".repeat(100)));
    }

    @Test
    public void estimateTokensIgnoresSurroundingWhitespace() {
        assertEquals(AgentActivity.estimateTokens("abcd"), AgentActivity.estimateTokens("   abcd   "));
    }

    // ---- aggregate ----

    @Test
    public void aggregateGroupsByProviderAndSumsInFirstSeenOrder() {
        List<AgentActivity.RunEntry> entries = List.of(
                entry(LlmProvider.GEMINI, 100, 40),
                entry(LlmProvider.OPENAI, 200, 60),
                entry(LlmProvider.GEMINI, 50, 10));
        List<AgentActivity.ProviderUsage> usage = AgentActivity.aggregate(entries);

        assertEquals(2, usage.size());
        // First-seen order: Gemini then OpenAI.
        assertEquals(LlmProvider.GEMINI, usage.get(0).provider());
        assertEquals(2, usage.get(0).calls());
        assertEquals(150, usage.get(0).inputTokens());
        assertEquals(50, usage.get(0).outputTokens());
        assertEquals(200, usage.get(0).totalTokens());
        assertEquals(LlmProvider.OPENAI, usage.get(1).provider());
        assertEquals(1, usage.get(1).calls());
        assertEquals(260, usage.get(1).totalTokens());
    }

    @Test
    public void aggregateHandlesEmptyOrNull() {
        assertTrue(AgentActivity.aggregate(List.of()).isEmpty());
        assertTrue(AgentActivity.aggregate(null).isEmpty());
    }

    // ---- formatUsage ----

    @Test
    public void formatUsageReportsNoCallsWhenEmpty() {
        assertEquals("No LLM calls yet.", AgentActivity.formatUsage(List.of()));
    }

    @Test
    public void formatUsageIncludesTotalsProvidersAndAnEstimateDisclaimer() {
        List<AgentActivity.RunEntry> entries = List.of(
                entry(LlmProvider.ANTHROPIC, 100, 100),   // 200
                entry(LlmProvider.OPENAI, 30, 20));         // 50
        String text = AgentActivity.formatUsage(entries);

        assertTrue(text.contains("Estimated usage"));
        assertTrue(text.contains("~250 tokens across 2 call(s)"));
        assertTrue(text.contains(LlmProvider.ANTHROPIC.label()));
        assertTrue(text.contains(LlmProvider.OPENAI.label()));
        assertTrue(text.toLowerCase().contains("not billed usage"));
    }
}
