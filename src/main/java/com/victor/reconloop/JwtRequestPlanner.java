package com.victor.reconloop;

import burp.api.montoya.http.message.requests.HttpRequest;
import java.util.List;
import java.util.Set;

/** Exact JWT mutations shared with live replay. Tokens and cracked secrets never enter preview text. */
final class JwtRequestPlanner {
    record WeakForgery(String secret, NativeRequestStep step) {}

    static NativeRequestStep baseline(HttpRequest request) {
        return recipe(request, "jwt-baseline", NativeRequestStep.Mutation.JWT_BASELINE, NativeRequestStep.Condition.ALWAYS).build();
    }

    static List<NativeRequestStep> noneVariants(HttpRequest request, String token) {
        return JwtAttackEngine.forgeNoneVariants(token).stream().map(forged -> recipe(replace(request, token, forged),
                "jwt-alg-none", NativeRequestStep.Mutation.JWT_NONE, NativeRequestStep.Condition.BASELINE_SUCCESS).build()).toList();
    }

    static WeakForgery weakSecret(HttpRequest request, String token) {
        String alg = JwtAttackEngine.headerAlg(token);
        String[] parts = token.split("\\.");
        if (alg == null || !alg.startsWith("hs") || parts.length < 3) return null;
        String secret = WebHygieneEngine.crackHmac(parts[0] + "." + parts[1], parts[2], alg);
        String forged = secret == null ? null : JwtAttackEngine.forgeWithSecret(token, secret, alg);
        return forged == null ? null : new WeakForgery(secret, recipe(replace(request, token, forged), "jwt-weak-secret",
                NativeRequestStep.Mutation.JWT_WEAK_SECRET, NativeRequestStep.Condition.BASELINE_SUCCESS).build());
    }

    static Iterable<NativeRequestStep> plan(HttpRequest request, String token) {
        return () -> {
            Object baseline = new Object();
            var first = java.util.stream.Stream.of(baseline(request).withConstraints(
                    new NativeRequestStep.Constraints(null, 0, 1, null, baseline)));
            var variants = noneVariants(request, token).stream();
            var weak = java.util.stream.Stream.of(token).map(value -> weakSecret(request, value))
                    .filter(java.util.Objects::nonNull).map(WeakForgery::step);
            return java.util.stream.Stream.concat(first, java.util.stream.Stream.concat(variants, weak)
                    .map(step -> step.withConstraints(new NativeRequestStep.Constraints(null, 0, 1, baseline, null)))).iterator();
        };
    }

    private static NativeRequestRecipe recipe(HttpRequest request, String probe, NativeRequestStep.Mutation mutation,
                                              NativeRequestStep.Condition condition) {
        return new NativeRequestRecipe(() -> request, probe, Set.of(RequestPolicy.Permission.AUTHENTICATION_OR_LOCKOUT),
                mutation, condition, condition == NativeRequestStep.Condition.ALWAYS ? "JWT baseline" : "requires a successful baseline before forgery replay", false);
    }

    private static HttpRequest replace(HttpRequest request, String original, String forged) {
        return HttpRequest.httpRequest(request.httpService(), request.toString().replace(original, forged));
    }
}
