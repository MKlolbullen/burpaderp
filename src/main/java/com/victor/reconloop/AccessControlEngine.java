package com.victor.reconloop;

import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.*;

/**
 * Autorize-style access-control / IDOR testing.
 *
 * <p>Given an "alternate identity" (a set of session headers, or none for unauthenticated), each
 * privileged in-scope request is replayed under that identity and the replayed response is compared
 * with the original. When the lower-privileged identity receives an equivalent successful response,
 * access control is likely broken — the highest-value bug class this extension can confirm.
 *
 * <p>The comparison verdict is a pure function so it can be unit-tested; the controller supplies the
 * two responses.
 */
final class AccessControlEngine {

    enum Verdict { BYPASSED, PARTIAL, ENFORCED, DIFFERENT }

    record Result(Verdict verdict, String severity, String detail) {}

    private final List<String[]> sessionHeaders; // {name, value}
    private final boolean unauthenticated;

    AccessControlEngine(String headerBlock, boolean unauthenticated) {
        this.sessionHeaders = parseHeaders(headerBlock);
        this.unauthenticated = unauthenticated;
    }

    boolean configured() { return unauthenticated || !sessionHeaders.isEmpty(); }

    /** Rebuilds {@code request} under the alternate identity (auth stripped and/or replaced). */
    HttpRequest applyIdentity(HttpRequest request) {
        HttpRequest modified = request
                .withRemovedHeader("Cookie")
                .withRemovedHeader("Authorization");
        for (String[] header : sessionHeaders) {
            modified = modified.withUpdatedHeader(header[0], header[1]);
        }
        return modified;
    }

    /** Pure verdict from the privileged vs. alternate-identity response characteristics. */
    static Result classify(int origStatus, int origLength, int replayStatus, int replayLength) {
        // Access control clearly enforced for the alternate identity.
        if (replayStatus == 401 || replayStatus == 403) {
            return new Result(Verdict.ENFORCED, "INFO",
                    "Alternate identity received " + replayStatus + " (access control enforced).");
        }
        if (replayStatus >= 300 && replayStatus < 400) {
            return new Result(Verdict.ENFORCED, "INFO",
                    "Alternate identity was redirected (" + replayStatus + "), likely to a login flow.");
        }

        boolean origSuccess = origStatus >= 200 && origStatus < 300;
        if (origSuccess && replayStatus == origStatus) {
            double ratio = origLength == 0 ? (replayLength == 0 ? 1.0 : 0.0)
                    : (double) replayLength / origLength;
            if (ratio >= 0.90 && ratio <= 1.10) {
                return new Result(Verdict.BYPASSED, "HIGH",
                        "Alternate identity received an equivalent " + replayStatus + " response ("
                                + replayLength + " vs " + origLength + " bytes) — probable broken access control / IDOR.");
            }
            return new Result(Verdict.PARTIAL, "MEDIUM",
                    "Alternate identity received the same status " + replayStatus + " but a different body ("
                            + replayLength + " vs " + origLength + " bytes) — review for partial data exposure.");
        }
        return new Result(Verdict.DIFFERENT, "INFO",
                "Alternate identity response differed (status " + replayStatus + " vs " + origStatus + ").");
    }

    static List<String[]> parseHeaders(String block) {
        if (block == null || block.isBlank()) return List.of();
        List<String[]> headers = new ArrayList<>();
        for (String line : block.split("\\R")) {
            String value = line.trim();
            if (value.isEmpty() || value.startsWith("#")) continue;
            int colon = value.indexOf(':');
            if (colon <= 0) continue;
            String name = value.substring(0, colon).trim();
            String headerValue = value.substring(colon + 1).trim();
            if (!name.isEmpty()) headers.add(new String[]{name, headerValue});
        }
        return headers;
    }
}
