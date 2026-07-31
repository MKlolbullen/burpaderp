package com.victor.reconloop;

import org.junit.Test;

import static org.junit.Assert.*;

public class IssueReporterFingerprintTest {

    @Test
    public void fingerprintsRawKeysWithoutRetainingSecretMaterial() {
        String raw = "hound-issue\0aws-access-key\0AKIA0123456789SECRET\0https://example.test/app.js";
        String fingerprint = IssueReporter.fingerprintKey(raw);

        assertNotNull(fingerprint);
        assertTrue(fingerprint.startsWith("sha256:"));
        assertEquals("sha256:".length() + 64, fingerprint.length());
        assertFalse(fingerprint.contains("AKIA"));
        assertFalse(fingerprint.contains("SECRET"));
    }

    @Test
    public void fingerprintingIsStableAndNormalisesNewlines() {
        assertEquals(IssueReporter.fingerprintKey("a\nb"), IssueReporter.fingerprintKey("a b"));
        assertEquals(IssueReporter.fingerprintKey("same-key"), IssueReporter.fingerprintKey("same-key"));
    }

    @Test
    public void alreadyFingerprintedKeysAreNotDoubleHashed() {
        String fingerprint = IssueReporter.fingerprintKey("finding-key");
        assertEquals(fingerprint, IssueReporter.fingerprintKey(fingerprint));
    }

    @Test
    public void nullKeyRemainsNull() {
        assertNull(IssueReporter.fingerprintKey(null));
    }
}
