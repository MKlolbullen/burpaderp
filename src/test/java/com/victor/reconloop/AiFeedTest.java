package com.victor.reconloop;

import org.junit.Test;

import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.Assert.*;

public class AiFeedTest {

    /** A store with a deterministic, advancing clock so timestamps are predictable in tests. */
    private static AiFeed.Store storeWithClock(int cap, AtomicLong clock) {
        return new AiFeed.Store(cap, clock::getAndIncrement);
    }

    // ---- Store: seq + timestamp ----

    @Test
    public void recordAssignsIncreasingSeqAndClockTimestamp() {
        AtomicLong clock = new AtomicLong(1000);
        AiFeed.Store store = storeWithClock(10, clock);

        AiFeed.Event a = store.record(AiFeed.Kind.TRIAGE, LlmProvider.OPENAI, "gpt", AiFeed.Outcome.OK, 10, 5, "t", "d");
        AiFeed.Event b = store.record(AiFeed.Kind.JS_REVIEW, LlmProvider.GEMINI, "g", AiFeed.Outcome.OK, 20, 0, "t2", "d2");

        assertEquals(1, a.seq());
        assertEquals(2, b.seq());
        assertEquals(1000, a.epochMillis());
        assertEquals(1001, b.epochMillis());
        assertEquals(2, store.size());
    }

    @Test
    public void recordClampsNegativeTokensAndDefaultsNullOutcomeAndText() {
        AiFeed.Store store = new AiFeed.Store();
        AiFeed.Event e = store.record(AiFeed.Kind.AGENT_ROUND, null, null, null, -5, -1, null, null);
        assertEquals(0, e.estInputTokens());
        assertEquals(0, e.estOutputTokens());
        assertEquals(AiFeed.Outcome.INFO, e.outcome());
        assertEquals("", e.title());
        assertEquals("", e.detail());
        assertNull(e.provider());
    }

    // ---- Store: capping / eviction ----

    @Test
    public void recordEvictsOldestWhenOverCap() {
        AiFeed.Store store = new AiFeed.Store(2, new AtomicLong(0)::getAndIncrement);
        store.record(AiFeed.Kind.TRIAGE, LlmProvider.OPENAI, "m", AiFeed.Outcome.OK, 1, 1, "first", "");
        store.record(AiFeed.Kind.TRIAGE, LlmProvider.OPENAI, "m", AiFeed.Outcome.OK, 1, 1, "second", "");
        store.record(AiFeed.Kind.TRIAGE, LlmProvider.OPENAI, "m", AiFeed.Outcome.OK, 1, 1, "third", "");

        List<AiFeed.Event> snap = store.snapshot();
        assertEquals(2, snap.size());
        // Oldest ("first") evicted; snapshot is oldest-first among survivors.
        assertEquals("second", snap.get(0).title());
        assertEquals("third", snap.get(1).title());
    }

    @Test
    public void capIsAtLeastOneEvenIfConstructedWithZeroOrNegative() {
        AiFeed.Store store = new AiFeed.Store(0, null);
        store.record(AiFeed.Kind.TRIAGE, LlmProvider.OPENAI, "m", AiFeed.Outcome.OK, 1, 1, "a", "");
        store.record(AiFeed.Kind.TRIAGE, LlmProvider.OPENAI, "m", AiFeed.Outcome.OK, 1, 1, "b", "");
        assertEquals(1, store.size());
        assertEquals("b", store.snapshot().get(0).title());
    }

    @Test
    public void clearEmptiesTheStore() {
        AiFeed.Store store = new AiFeed.Store();
        store.record(AiFeed.Kind.TRIAGE, LlmProvider.OPENAI, "m", AiFeed.Outcome.OK, 1, 1, "a", "");
        store.clear();
        assertEquals(0, store.size());
        assertTrue(store.snapshot().isEmpty());
    }

    // ---- outcomeFor ----

    @Test
    public void outcomeForMapsFailureSentinelsToError() {
        assertEquals(AiFeed.Outcome.ERROR, AiFeed.outcomeFor(null));
        assertEquals(AiFeed.Outcome.ERROR, AiFeed.outcomeFor("[error] boom"));
        assertEquals(AiFeed.Outcome.ERROR, AiFeed.outcomeFor("[HTTP 429] rate limited"));
        assertEquals(AiFeed.Outcome.ERROR, AiFeed.outcomeFor("[warning] truncated"));
        assertEquals(AiFeed.Outcome.OK, AiFeed.outcomeFor("A perfectly good answer."));
        assertEquals(AiFeed.Outcome.OK, AiFeed.outcomeFor(""));
    }

    // ---- aggregate ----

    @Test
    public void aggregateGroupsByProviderInFirstSeenOrderAndSkipsProviderlessEvents() {
        AiFeed.Store store = new AiFeed.Store();
        store.record(AiFeed.Kind.JS_REVIEW, LlmProvider.GEMINI, "g", AiFeed.Outcome.OK, 100, 40, "", "");
        store.record(AiFeed.Kind.TRIAGE, LlmProvider.OPENAI, "o", AiFeed.Outcome.OK, 200, 60, "", "");
        store.record(AiFeed.Kind.JS_REVIEW, LlmProvider.GEMINI, "g", AiFeed.Outcome.OK, 50, 10, "", "");
        store.record(AiFeed.Kind.ESCALATION, null, null, AiFeed.Outcome.HELD, 0, 0, "", ""); // no provider

        List<AiFeed.ProviderUsage> usage = AiFeed.aggregate(store.snapshot());
        assertEquals(2, usage.size());
        assertEquals(LlmProvider.GEMINI, usage.get(0).provider());
        assertEquals(2, usage.get(0).calls());
        assertEquals(150, usage.get(0).inputTokens());
        assertEquals(50, usage.get(0).outputTokens());
        assertEquals(200, usage.get(0).totalTokens());
        assertEquals(LlmProvider.OPENAI, usage.get(1).provider());
        assertEquals(260, usage.get(1).totalTokens());
    }

    @Test
    public void aggregateHandlesEmptyOrNull() {
        assertTrue(AiFeed.aggregate(List.of()).isEmpty());
        assertTrue(AiFeed.aggregate(null).isEmpty());
    }

    // ---- summarize ----

    @Test
    public void summarizeReportsNoActivityWhenEmpty() {
        assertEquals("No AI activity yet.", AiFeed.summarize(List.of()));
        assertEquals("No AI activity yet.", AiFeed.summarize(null));
    }

    @Test
    public void summarizeIncludesCountsKindsProvidersAndDisclaimer() {
        AiFeed.Store store = new AiFeed.Store();
        store.record(AiFeed.Kind.TRIAGE, LlmProvider.ANTHROPIC, "m", AiFeed.Outcome.OK, 100, 100, "", "");
        store.record(AiFeed.Kind.AGENT_ROUND, LlmProvider.OPENAI, "m", AiFeed.Outcome.OK, 30, 20, "", "");
        store.record(AiFeed.Kind.ESCALATION, null, null, AiFeed.Outcome.HELD, 0, 0, "", "");

        String text = AiFeed.summarize(store.snapshot());
        assertTrue(text.contains("3 event(s)"));
        assertTrue(text.contains("~250 est tokens"));
        assertTrue(text.contains(AiFeed.Kind.TRIAGE.label()));
        assertTrue(text.contains(AiFeed.Kind.ESCALATION.label()));
        assertTrue(text.contains(LlmProvider.ANTHROPIC.label()));
        assertTrue(text.contains(LlmProvider.OPENAI.label()));
        assertTrue(text.toLowerCase().contains("not billed usage"));
    }
}
