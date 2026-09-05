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

    @Test
    public void pathAndJsonLabelsAreDistinct() {
        InsertionPoint path = new InsertionPoint(InsertionPoint.Kind.PATH, "123", "123", null, 3);
        assertEquals("path[3]", path.label());
        InsertionPoint json = new InsertionPoint(InsertionPoint.Kind.JSON, "/user/role", "guest", null);
        assertEquals("json:/user/role", json.label());
    }

    // ---- path helpers ----

    @Test
    public void encodePathSegmentKeepsUnreservedAndPercentEncodesTheRest() {
        assertEquals("abcXYZ-._~09", InsertionPoint.encodePathSegment("abcXYZ-._~09"));
        assertEquals("a%2Fb", InsertionPoint.encodePathSegment("a/b"));          // slash stays in one segment
        assertEquals("%27%20OR%20%271%27", InsertionPoint.encodePathSegment("' OR '1'"));
        assertEquals("", InsertionPoint.encodePathSegment(null));
    }

    @Test
    public void replacePathSegmentSwapsOneSegmentAndKeepsSlashes() {
        // "/api/users/123" -> split ["", "api", "users", "123"]; index 3 is "123".
        assertEquals("/api/users/INJ", InsertionPoint.replacePathSegment("/api/users/123", 3, "INJ"));
        assertEquals("/api/INJ/123", InsertionPoint.replacePathSegment("/api/users/123", 2, "INJ"));
        // Out-of-range index leaves the path unchanged.
        assertEquals("/api/users/123", InsertionPoint.replacePathSegment("/api/users/123", 9, "INJ"));
    }

    @Test
    public void querySuffixExtractsTheQueryOrEmpty() {
        assertEquals("?a=1&b=2", InsertionPoint.querySuffix("/x/y?a=1&b=2"));
        assertEquals("", InsertionPoint.querySuffix("/x/y"));
        assertEquals("", InsertionPoint.querySuffix(null));
    }

    // ---- JSON helpers ----

    @Test
    public void looksLikeJsonByContentTypeOrBodyOpener() {
        assertTrue(InsertionPoint.looksLikeJson("application/json; charset=utf-8", ""));
        assertTrue(InsertionPoint.looksLikeJson(null, "  {\"a\":1}"));
        assertTrue(InsertionPoint.looksLikeJson(null, "[1,2,3]"));
        assertFalse(InsertionPoint.looksLikeJson("application/x-www-form-urlencoded", "a=1&b=2"));
        assertFalse(InsertionPoint.looksLikeJson(null, null));
    }

    @Test
    public void setJsonLeafReplacesTheTargetedValue() {
        String out = InsertionPoint.setJsonLeaf("{\"user\":{\"role\":\"guest\"}}", "/user/role", "admin");
        assertEquals("{\"user\":{\"role\":\"admin\"}}", out);
    }

    @Test
    public void setJsonLeafReturnsOriginalBodyOnUnresolvablePointerOrNonJson() {
        assertEquals("{\"a\":1}", InsertionPoint.setJsonLeaf("{\"a\":1}", "/missing", "x"));
        assertEquals("not json", InsertionPoint.setJsonLeaf("not json", "/a", "x"));
    }
}
