package com.victor.reconloop.contracts;

/**
 * Evidence lifecycle from docs/SAFETY_ROADMAP.md / issue #44.
 * A detector must not jump from a single weak signal to CONFIRMED.
 */
public enum VerificationState {
    SIGNAL,
    CANDIDATE,
    REPRODUCED,
    CONFIRMED,
    EXPLOITABLE,
    REJECTED
}
