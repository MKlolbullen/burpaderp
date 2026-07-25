package com.victor.reconloop;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Pure payload-encoding helpers for the opt-in corpus-fuzz active test: URL, HTML-entity, and
 * Base64 encoding, plus a few chained (combined) pipelines. Dependency-free so it's directly
 * unit-testable; no Montoya types involved.
 */
final class PayloadEncoder {

    enum Encoding { RAW, URL, HTML, BASE64, DOUBLE_URL, BASE64_THEN_URL, URL_THEN_BASE64 }

    private PayloadEncoder() {}

    static String encode(String payload, Encoding encoding) {
        if (payload == null) return null;
        return switch (encoding) {
            case RAW -> payload;
            case URL -> urlEncode(payload);
            case HTML -> htmlEncode(payload);
            case BASE64 -> base64Encode(payload);
            case DOUBLE_URL -> urlEncode(urlEncode(payload));
            case BASE64_THEN_URL -> urlEncode(base64Encode(payload));
            case URL_THEN_BASE64 -> base64Encode(urlEncode(payload));
        };
    }

    static String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }

    static String htmlEncode(String value) {
        StringBuilder out = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '&' -> out.append("&amp;");
                case '<' -> out.append("&lt;");
                case '>' -> out.append("&gt;");
                case '"' -> out.append("&quot;");
                case '\'' -> out.append("&#39;");
                default -> out.append(c);
            }
        }
        return out.toString();
    }

    static String base64Encode(String value) {
        return Base64.getEncoder().encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }
}
