package com.victor.reconloop;

import org.junit.Test;

import static org.junit.Assert.*;

public class VerificationStateTest {

    @Test
    public void legacyBooleanMapsConservativelyToEvidenceLifecycle() {
        assertEquals(VerificationState.REPRODUCED, VerificationState.fromLegacyConfirmed(true));
        assertEquals(VerificationState.SIGNAL, VerificationState.fromLegacyConfirmed(false));
    }

    @Test
    public void onlyReproducedOrStrongerStatesAreReportable() {
        assertFalse(VerificationState.SIGNAL.isReportable());
        assertFalse(VerificationState.CANDIDATE.isReportable());
        assertTrue(VerificationState.REPRODUCED.isReportable());
        assertTrue(VerificationState.CONFIRMED.isReportable());
        assertTrue(VerificationState.EXPLOITABLE.isReportable());
        assertFalse(VerificationState.REJECTED.isReportable());
    }

    @Test
    public void activeFindingRetainsLegacyConstructorWithoutInflatingState() {
        ActiveTestEngine.ActiveFinding finding = new ActiveTestEngine.ActiveFinding(
                "HIGH", "SSTI", "template", "arithmetic evaluated", true, "https://example.test/");

        assertEquals(VerificationState.REPRODUCED, finding.verificationState());
        assertTrue(finding.confirmed());
    }
}
