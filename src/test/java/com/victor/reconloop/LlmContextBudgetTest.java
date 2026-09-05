package com.victor.reconloop;

import org.junit.Test;

import static org.junit.Assert.*;

/**
 * Covers the input-budget truncation ({@link LlmClient#budgetInput}) and the Anthropic prompt-cache
 * request shape ({@link LlmProvider#requestBody}) added alongside it.
 */
public class LlmContextBudgetTest {

    @Test
    public void underBudgetInputIsUnchanged() {
        String input = "finding-1\nfinding-2\nfinding-3";
        assertEquals(input, LlmClient.budgetInput(input, 200_000));
    }

    @Test
    public void nullInputBecomesEmpty() {
        assertEquals("", LlmClient.budgetInput(null, 200_000));
    }

    @Test
    public void overBudgetTruncatesAndAnnounces() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 5_000; i++) sb.append("finding line number ").append(i).append('\n');
        String input = sb.toString();

        String out = LlmClient.budgetInput(input, 1_000);

        assertTrue("result must stay within budget", out.length() <= 1_000);
        assertTrue("truncation must be announced, not silent", out.contains("truncated to fit the model input budget"));
        assertTrue("notice must report omitted characters", out.contains("characters"));
    }

    @Test
    public void truncationPrefersLineBoundary() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 500; i++) sb.append("aaaaaaaaaa").append('\n'); // 11 chars per line
        String input = sb.toString();

        String out = LlmClient.budgetInput(input, 300);
        String kept = out.substring(0, out.indexOf("\n\n[... truncated"));

        // Kept content ends exactly on a line boundary — no half-finding slice.
        assertTrue("kept prefix should end at a newline boundary", kept.endsWith("\n"));
    }

    @Test
    public void anthropicBodyMarksSystemBlockCacheable() {
        String body = LlmProvider.ANTHROPIC.requestBody("claude-opus-5", "SYSTEM PROMPT", "user text", 4096);
        assertTrue("system must be a content-block array", body.contains("\"system\":[{\"type\":\"text\""));
        assertTrue("system block must carry cache_control", body.contains("\"cache_control\":{\"type\":\"ephemeral\"}"));
        assertTrue("system text must be present", body.contains("SYSTEM PROMPT"));
    }

    @Test
    public void anthropicBodyWithEmptySystemStaysPlainString() {
        String body = LlmProvider.ANTHROPIC.requestBody("claude-opus-5", "", "user text", 4096);
        // No empty cached block: an empty system falls back to a plain "" so the request stays valid.
        assertTrue(body.contains("\"system\":\"\""));
        assertFalse(body.contains("cache_control"));
    }
}
