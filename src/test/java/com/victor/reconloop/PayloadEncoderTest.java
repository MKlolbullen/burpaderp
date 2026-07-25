package com.victor.reconloop;

import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.Assert.*;

public class PayloadEncoderTest {

    @Test
    public void rawEncodingReturnsPayloadUnchanged() {
        assertEquals("<script>alert(1)</script>", PayloadEncoder.encode("<script>alert(1)</script>", PayloadEncoder.Encoding.RAW));
    }

    @Test
    public void urlEncodingEscapesMetacharacters() {
        String encoded = PayloadEncoder.encode("<script>", PayloadEncoder.Encoding.URL);
        assertEquals("%3Cscript%3E", encoded);
    }

    @Test
    public void urlEncodingUsesPercentTwentyForSpaces() {
        String encoded = PayloadEncoder.urlEncode("a b");
        assertEquals("a%20b", encoded);
    }

    @Test
    public void htmlEncodingEscapesAllFiveMetacharacters() {
        String encoded = PayloadEncoder.encode("<>&\"'", PayloadEncoder.Encoding.HTML);
        assertEquals("&lt;&gt;&amp;&quot;&#39;", encoded);
    }

    @Test
    public void htmlEncodingLeavesOrdinaryTextUntouched() {
        assertEquals("hello world 123", PayloadEncoder.encode("hello world 123", PayloadEncoder.Encoding.HTML));
    }

    @Test
    public void base64EncodingRoundTrips() {
        String payload = "' OR '1'='1";
        String encoded = PayloadEncoder.encode(payload, PayloadEncoder.Encoding.BASE64);
        String decoded = new String(Base64.getDecoder().decode(encoded), StandardCharsets.UTF_8);
        assertEquals(payload, decoded);
    }

    @Test
    public void doubleUrlEncodingAppliesUrlEncodingTwice() {
        String payload = "<";
        String once = PayloadEncoder.urlEncode(payload);
        String twice = PayloadEncoder.urlEncode(once);
        assertEquals(twice, PayloadEncoder.encode(payload, PayloadEncoder.Encoding.DOUBLE_URL));
        assertNotEquals(once, twice);
    }

    @Test
    public void base64ThenUrlEncodesTheBase64OutputNotTheOriginalPayload() {
        String payload = "a+b/c=";
        String expected = PayloadEncoder.urlEncode(PayloadEncoder.base64Encode(payload));
        assertEquals(expected, PayloadEncoder.encode(payload, PayloadEncoder.Encoding.BASE64_THEN_URL));
    }

    @Test
    public void urlThenBase64EncodesTheUrlEncodedOutput() {
        String payload = "<script>";
        String expected = PayloadEncoder.base64Encode(PayloadEncoder.urlEncode(payload));
        assertEquals(expected, PayloadEncoder.encode(payload, PayloadEncoder.Encoding.URL_THEN_BASE64));
    }

    @Test
    public void nullPayloadEncodesToNullForEveryEncoding() {
        for (PayloadEncoder.Encoding encoding : PayloadEncoder.Encoding.values()) {
            assertNull(PayloadEncoder.encode(null, encoding));
        }
    }
}
