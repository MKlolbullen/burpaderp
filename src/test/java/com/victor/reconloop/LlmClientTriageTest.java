package com.victor.reconloop;

import org.junit.Test;

import java.util.List;

import static org.junit.Assert.*;

public class LlmClientTriageTest {

    @Test
    public void parsesStrictJsonVerdicts() {
        String raw = "{\"verdicts\":["
                + "{\"index\":1,\"verdict\":\"LIKELY_FP\",\"reasoning\":\"placeholder value\"},"
                + "{\"index\":2,\"verdict\":\"LIKELY_TP\",\"reasoning\":\"live-looking token\"},"
                + "{\"index\":3,\"verdict\":\"UNCERTAIN\",\"reasoning\":\"not enough context\"}"
                + "]}";

        List<LlmClient.TriageVerdict> verdicts = LlmClient.parseTriageVerdicts(raw);

        assertEquals(3, verdicts.size());
        assertEquals(1, verdicts.get(0).index());
        assertEquals("LIKELY_FP", verdicts.get(0).verdict());
        assertEquals("placeholder value", verdicts.get(0).reasoning());
        assertEquals("LIKELY_TP", verdicts.get(1).verdict());
        assertEquals("UNCERTAIN", verdicts.get(2).verdict());
    }

    @Test
    public void toleratesMarkdownCodeFencesAndSurroundingProse() {
        String raw = "Sure, here is the JSON:\n```json\n"
                + "{\"verdicts\":[{\"index\":1,\"verdict\":\"LIKELY_FP\",\"reasoning\":\"x\"}]}"
                + "\n```\nLet me know if you need anything else.";

        List<LlmClient.TriageVerdict> verdicts = LlmClient.parseTriageVerdicts(raw);

        assertEquals(1, verdicts.size());
        assertEquals("LIKELY_FP", verdicts.get(0).verdict());
    }

    @Test
    public void missingOptionalFieldsFallBackToDefaults() {
        String raw = "{\"verdicts\":[{\"index\":1}]}";

        List<LlmClient.TriageVerdict> verdicts = LlmClient.parseTriageVerdicts(raw);

        assertEquals(1, verdicts.size());
        assertEquals("UNCERTAIN", verdicts.get(0).verdict());
        assertEquals("", verdicts.get(0).reasoning());
    }

    @Test
    public void entriesWithoutAnIndexAreSkipped() {
        String raw = "{\"verdicts\":[{\"verdict\":\"LIKELY_FP\"},{\"index\":2,\"verdict\":\"LIKELY_TP\"}]}";

        List<LlmClient.TriageVerdict> verdicts = LlmClient.parseTriageVerdicts(raw);

        assertEquals(1, verdicts.size());
        assertEquals(2, verdicts.get(0).index());
    }

    @Test
    public void malformedOrNonJsonInputYieldsEmptyList() {
        assertTrue(LlmClient.parseTriageVerdicts("not json at all").isEmpty());
        assertTrue(LlmClient.parseTriageVerdicts(null).isEmpty());
        assertTrue(LlmClient.parseTriageVerdicts("{\"verdicts\":[{\"index\":1,\"verdict\":").isEmpty());
    }

    @Test
    public void bareArrayWithoutWrapperObjectIsAlsoAccepted() {
        String raw = "[{\"index\":1,\"verdict\":\"LIKELY_TP\",\"reasoning\":\"r\"}]";

        List<LlmClient.TriageVerdict> verdicts = LlmClient.parseTriageVerdicts(raw);

        assertEquals(1, verdicts.size());
        assertEquals("LIKELY_TP", verdicts.get(0).verdict());
    }
}
