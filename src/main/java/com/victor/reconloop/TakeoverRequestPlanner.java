package com.victor.reconloop;

import burp.api.montoya.http.message.requests.HttpRequest;
import java.util.List;
import java.util.Set;

final class TakeoverRequestPlanner {
    static Iterable<NativeRequestStep> plan(String host) {
        return () -> List.of("https://", "http://").stream().map(scheme -> step(host, scheme)).iterator();
    }

    static NativeRequestStep step(String host, String scheme) {
        return new NativeRequestRecipe(() -> HttpRequest.httpRequestFromUrl(scheme + host + "/"), "subdomain-takeover", Set.of(),
                NativeRequestStep.Mutation.TAKEOVER, scheme.equals("https://") ? NativeRequestStep.Condition.ALWAYS : NativeRequestStep.Condition.FALLBACK,
                scheme.equals("https://") ? "HTTPS root check" : "HTTP fallback unless HTTPS fingerprint matches", false).build();
    }
}
