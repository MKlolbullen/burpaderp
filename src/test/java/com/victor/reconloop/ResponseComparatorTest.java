package com.victor.reconloop;

import org.junit.Test;

import java.util.List;
import java.util.Set;

import static org.junit.Assert.*;

public class ResponseComparatorTest {

    @Test
    public void normalisesVolatileRequestIdsAndTimestamps() {
        String first = """
                <html><body>
                request_id=550e8400-e29b-41d4-a716-446655440000
                generated=2026-10-17T12:00:00Z
                result=alice
                </body></html>
                """;
        String second = """
                <html><body>
                request_id=123e4567-e89b-42d3-a456-426614174000
                generated=2026-10-17T12:00:07Z
                result=alice
                </body></html>
                """;

        assertTrue(ResponseComparator.samePage(first, second));
    }

    @Test
    public void canonicalJsonIgnoresConfiguredVolatileFieldsAndKeyOrder() {
        String first = "{"requestId":"abc","name":"alice","roles":["user"]}";
        String second = "{"roles":["user"],"name":"alice","requestId":"xyz"}";

        assertEquals(
                ResponseComparator.canonicalizeJson(first, Set.of("requestId")),
                ResponseComparator.canonicalizeJson(second, Set.of("requestId")));
        assertTrue(ResponseComparator.samePage(first, second));
    }

    @Test
    public void materiallyDifferentPagesDoNotCompareEqual() {
        String allowed = "<html><h1>Admin</h1><p>secret account data export delete</p></html>";
        String denied = "<html><h1>Login</h1><p>please authenticate to continue</p></html>";

        assertFalse(ResponseComparator.samePage(allowed, denied));
        assertTrue(ResponseComparator.similarity(allowed, denied) < 0.60);
    }

    @Test
    public void stableRepeatedDelayIsDetectedWithMedianAndMad() {
        ResponseComparator.TimingAnalysis analysis = ResponseComparator.analyzeTiming(
                List.of(120L, 135L, 128L),
                List.of(5120L, 5190L, 5075L),
                5_000L);

        assertTrue(analysis.delayed());
        assertTrue(analysis.medianDeltaMillis() >= 4_000L);
        assertEquals(3, analysis.consistentDelayedSamples());
    }

    @Test
    public void jitteryBaselineDoesNotCreateTimingFinding() {
        ResponseComparator.TimingAnalysis analysis = ResponseComparator.analyzeTiming(
                List.of(200L, 2200L, 4200L),
                List.of(5100L, 5300L, 5500L),
                5_000L);

        assertFalse(analysis.delayed());
        assertTrue(analysis.baselineMadMillis() >= 2_000L);
    }

    @Test
    public void singleSlowResponseIsNotEnoughEvidence() {
        ResponseComparator.TimingAnalysis analysis = ResponseComparator.analyzeTiming(
                List.of(100L, 120L, 110L),
                List.of(110L, 5200L, 130L),
                5_000L);

        assertFalse(analysis.delayed());
        assertEquals(1, analysis.consistentDelayedSamples());
    }

    @Test
    public void requiresAtLeastThreeSamplesPerSide() {
        assertFalse(ResponseComparator.analyzeTiming(
                List.of(100L, 110L), List.of(5100L, 5200L), 5_000L).delayed());
    }

    @Test
    public void medianAndMadAreRobustToOneOutlier() {
        assertEquals(110L, ResponseComparator.median(List.of(100L, 110L, 9000L)));
        assertEquals(10L, ResponseComparator.mad(List.of(100L, 110L, 9000L)));
    }
}
