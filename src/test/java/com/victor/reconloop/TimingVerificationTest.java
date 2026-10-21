package com.victor.reconloop;

import org.junit.Test;
import java.util.List;
import java.util.Map;
import static org.junit.Assert.*;

public class TimingVerificationTest {
    @Test public void threeStableMatchedPairsReproduceTheDelayWithRawSamplesAndMad() {
        var assessment = TimingVerification.paired(List.of(100L, 120L, 110L), List.of(5100L, 5120L, 5110L));
        assertEquals(VerificationState.REPRODUCED, assessment.state());
        assertTrue(assessment.rationale().contains("baseline=[100, 120, 110]"));
        assertTrue(assessment.rationale().contains("MAD=10"));
        assertTrue(assessment.rationale().contains("exploit impact remain unproven"));
    }
    @Test public void oneOrTwoPairsCannotBePromotedDespiteLargeDelay() {
        for (int count : List.of(1, 2)) assertEquals(VerificationState.CANDIDATE,
                TimingVerification.paired(List.of(100L, 100L).subList(0, count), List.of(5100L, 5100L).subList(0, count)).state());
    }
    @Test public void isolatedOutlierAndBaselineJitterRemainCandidates() {
        assertEquals(VerificationState.CANDIDATE, TimingVerification.paired(List.of(100L, 100L, 100L), List.of(5100L, 100L, 100L)).state());
        assertEquals(VerificationState.CANDIDATE, TimingVerification.paired(List.of(100L, 3000L, 6000L), List.of(5100L, 8000L, 11000L)).state());
    }
    @Test public void matchingControlsPreventUnpairedMediansFromPromotingAnAnomaly() {
        var controls = List.of(100L, 10_000L, 100L); var payload = List.of(5100L, 5100L, 100L);
        assertTrue(ResponseComparator.analyzeTiming(controls, payload, 5000).delayed());
        assertEquals(VerificationState.CANDIDATE, TimingVerification.paired(controls, payload).state());
    }
    @Test public void noDelayIsOnlyASignalAndInvalidOrExcessPairsAreRejected() {
        assertEquals(VerificationState.SIGNAL, TimingVerification.paired(List.of(100L, 100L, 100L), List.of(100L, 120L, 110L)).state());
        assertEquals(VerificationState.SIGNAL, TimingVerification.paired(List.of(), List.of()).state());
        assertThrows(IllegalArgumentException.class, () -> TimingVerification.paired(List.of(100L), List.of()));
        assertThrows(IllegalArgumentException.class, () -> TimingVerification.paired(List.of(-1L), List.of(5000L)));
        assertThrows(IllegalArgumentException.class, () -> TimingVerification.paired(List.of(0L,0L,0L,0L), List.of(5000L,5000L,5000L,5000L)));
    }
    @Test public void errorsMissingResponsesErrorStatusesAndUnknownDurationsAreNotSamples() {
        try (FakeMontoya fake = new FakeMontoya()) {
            var request = fake.request("https://api.example.test/");
            for (int status : List.of(0, 100, 400, 403, 429, 500, 503)) {
                var result = new ActiveRequestGateway.Result(RequestPolicy.Decision.allow(), FakeMontoya.pair(request, FakeMontoya.response(status,"",Map.of())), null, true, null, 5_000_000_000L);
                assertEquals(-1, TimingVerification.sampleMillis(result));
            }
            var rr = FakeMontoya.pair(request, FakeMontoya.response(200,"",Map.of()));
            assertEquals(-1, TimingVerification.sampleMillis(new ActiveRequestGateway.Result(RequestPolicy.Decision.allow(), rr, null, true)));
            assertEquals(-1, TimingVerification.sampleMillis(new ActiveRequestGateway.Result(RequestPolicy.Decision.allow(), rr, new java.io.IOException(), true, null, 5_000_000_000L)));
            assertEquals(-1, TimingVerification.sampleMillis(new ActiveRequestGateway.Result(RequestPolicy.Decision.allow(), FakeMontoya.pair(request,null), null, true, null, 5_000_000_000L)));
            assertEquals(-1, TimingVerification.sampleMillis(new ActiveRequestGateway.Result(RequestPolicy.Decision.allow(), null, null, true, null, 5_000_000_000L)));
            assertEquals(5000, TimingVerification.sampleMillis(new ActiveRequestGateway.Result(RequestPolicy.Decision.allow(), rr, null, true, null, 5_000_000_000L)));
            var broken = FakeMontoya.proxy(burp.api.montoya.http.message.HttpRequestResponse.class, (self, method, args) -> { throw new IllegalStateException("optional data unavailable"); });
            assertEquals(-1, TimingVerification.sampleMillis(new ActiveRequestGateway.Result(RequestPolicy.Decision.allow(), broken, null, true, null, 5_000_000_000L)));
        }
    }
}
