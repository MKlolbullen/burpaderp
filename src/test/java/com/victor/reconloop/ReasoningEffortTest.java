package com.victor.reconloop;

import org.junit.Test;

import static org.junit.Assert.*;

public class ReasoningEffortTest {

    @Test
    public void anthropicEffortIsTheLowercaseLevelName() {
        assertEquals("low", ReasoningEffort.LOW.anthropicEffort());
        assertEquals("high", ReasoningEffort.HIGH.anthropicEffort());
        assertEquals("xhigh", ReasoningEffort.XHIGH.anthropicEffort());
        assertEquals("max", ReasoningEffort.MAX.anthropicEffort());
    }

    @Test
    public void openAiReasoningEffortClampsToThreeLevels() {
        assertEquals("low", ReasoningEffort.LOW.openAiReasoningEffort());
        assertEquals("medium", ReasoningEffort.MEDIUM.openAiReasoningEffort());
        assertEquals("high", ReasoningEffort.HIGH.openAiReasoningEffort());
        // Anthropic's top two levels have no OpenAI equivalent — both collapse to "high".
        assertEquals("high", ReasoningEffort.XHIGH.openAiReasoningEffort());
        assertEquals("high", ReasoningEffort.MAX.openAiReasoningEffort());
    }

    @Test
    public void geminiThinkingBudgetIsStrictlyMonotonicInEffort() {
        int prev = -1;
        for (ReasoningEffort effort : ReasoningEffort.values()) {
            int budget = effort.geminiThinkingBudget();
            assertTrue("budget should increase with effort", budget > prev);
            prev = budget;
        }
    }

    @Test
    public void fromLabelIsCaseInsensitive() {
        assertEquals(ReasoningEffort.MAX, ReasoningEffort.fromLabel("max"));
        assertEquals(ReasoningEffort.MAX, ReasoningEffort.fromLabel("MAX"));
        assertEquals(ReasoningEffort.XHIGH, ReasoningEffort.fromLabel(" xHigh "));
    }

    @Test
    public void fromLabelDefaultsToHighForUnknownOrBlank() {
        assertEquals(ReasoningEffort.HIGH, ReasoningEffort.fromLabel(null));
        assertEquals(ReasoningEffort.HIGH, ReasoningEffort.fromLabel(""));
        assertEquals(ReasoningEffort.HIGH, ReasoningEffort.fromLabel("turbo"));
    }
}
