package com.victor.reconloop;

import java.util.List;

/** Conservative timing evidence: completed 2xx/3xx responses and repeated bounded controls. */
final class TimingVerification {
    static final int SAMPLES = 3;
    static final long EXPECTED_DELAY_MILLIS = 5_000;

    static long sampleMillis(ActiveRequestGateway.Result result) {
        try {
            if (result == null || !result.dispatched() || result.error() != null || result.transportElapsedNanos() < 0
                    || result.response() == null || result.response().response() == null) return -1;
            int status = result.response().response().statusCode();
            if (status < 200 || status >= 400) return -1;
            return result.transportElapsedNanos() / 1_000_000;
        } catch (RuntimeException unavailable) { return -1; } // Optional metrics never suppress a completed response.
    }

    record Assessment(VerificationState state, String rationale) {}

    static Assessment paired(List<Long> baseline, List<Long> payload) {
        if (baseline.size() != payload.size() || baseline.size() > SAMPLES
                || baseline.stream().anyMatch(v -> v == null || v < 0) || payload.stream().anyMatch(v -> v == null || v < 0))
            throw new IllegalArgumentException("matched valid timing pairs required");
        int delayedPairs = 0;
        for (int i = 0; i < baseline.size(); i++)
            if (payload.get(i) - baseline.get(i) >= EXPECTED_DELAY_MILLIS - 1_000) delayedPairs++;
        var timing = ResponseComparator.analyzeTiming(baseline, payload, EXPECTED_DELAY_MILLIS);
        boolean repeated = baseline.size() == SAMPLES && timing.delayed() && delayedPairs >= 2;
        VerificationState state = repeated ? VerificationState.REPRODUCED
                : delayedPairs > 0 ? VerificationState.CANDIDATE : VerificationState.SIGNAL;
        return new Assessment(state, "Transport invocation durations in ms (excluding gateway resolution/admission, engine pacing and evidence capture): baseline="
                + baseline + ", payload=" + payload + "; baseline median=" + timing.baselineMedianMillis()
                + " (MAD=" + timing.baselineMadMillis() + "), payload median=" + timing.payloadMedianMillis()
                + " (MAD=" + timing.payloadMadMillis() + "), delta=" + timing.medianDeltaMillis()
                + "; delayed matched pairs=" + delayedPairs + "/" + baseline.size() + ". "
                + (repeated ? "Repeated timing signal; interpreter execution and exploit impact remain unproven."
                : "Insufficient or inconsistent timing evidence; no reproduced delay is claimed."));
    }
}
