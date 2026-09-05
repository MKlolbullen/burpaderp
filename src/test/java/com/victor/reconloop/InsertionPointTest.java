package com.victor.reconloop;

import burp.api.montoya.http.message.params.HttpParameterType;
import org.junit.Test;

import static org.junit.Assert.*;

public class InsertionPointTest {

    // ---- isFuzzableHeader ----

    @Test
    public void commonlyTrustedHeadersAreFuzzable() {
        assertTrue(InsertionPoint.isFuzzableHeader("User-Agent"));
        assertTrue(InsertionPoint.isFuzzableHeader("Referer"));
        assertTrue(InsertionPoint.isFuzzableHeader("X-Forwarded-For"));
        assertTrue(InsertionPoint.isFuzzableHeader("x-forwarded-host"));   // case-insensitive
        assertTrue(InsertionPoint.isFuzzableHeader("  True-Client-IP  "));  // trimmed
    }

    @Test
    public void transportAndAuthHeadersAreNotFuzzable() {
        assertFalse(InsertionPoint.isFuzzableHeader("Host"));
        assertFalse(InsertionPoint.isFuzzableHeader("Content-Length"));
        assertFalse(InsertionPoint.isFuzzableHeader("Authorization"));
        assertFalse(InsertionPoint.isFuzzableHeader("Cookie"));
        assertFalse(InsertionPoint.isFuzzableHeader("Content-Type"));
        assertFalse(InsertionPoint.isFuzzableHeader(null));
        assertFalse(InsertionPoint.isFuzzableHeader(""));
    }

    // ---- label ----

    @Test
    public void parameterLabelIsTheParameterName() {
        InsertionPoint p = new InsertionPoint(InsertionPoint.Kind.PARAM, "q", "v", HttpParameterType.URL);
        assertEquals("q", p.label());
    }

    @Test
    public void headerLabelIsPrefixed() {
        InsertionPoint p = new InsertionPoint(InsertionPoint.Kind.HEADER, "X-Forwarded-For", "1.2.3.4", null);
        assertEquals("header:X-Forwarded-For", p.label());
    }
}
