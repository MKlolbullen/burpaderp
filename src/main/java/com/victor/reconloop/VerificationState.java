package com.victor.reconloop;

/**
 * Evidence lifecycle for a finding.
 *
 * <p>A detector's first observation is not automatically proof of impact.  Keeping the lifecycle
 * explicit lets the UI, issue sink, and later run history distinguish a lead from a reproduced
 * condition and from a confirmed exploit path.
 */
enum VerificationState {
    SIGNAL,
    CANDIDATE,
    REPRODUCED,
    CONFIRMED,
    EXPLOITABLE,
    REJECTED;

    /**
     * Compatibility bridge for older detectors that only exposed {@code confirmed: boolean}.
     * A legacy true value means the detector reproduced its expected signal; it does not, by
     * itself, establish real-world exploitability.
     */
    static VerificationState fromLegacyConfirmed(boolean confirmed) {
        return confirmed ? REPRODUCED : SIGNAL;
    }

    /** Findings reproduced or stronger are suitable for the native issue sink. */
    boolean isReportable() {
        return this == REPRODUCED || this == CONFIRMED || this == EXPLOITABLE;
    }

    String displayLabel() {
        return name().toLowerCase(java.util.Locale.ROOT);
    }
}
