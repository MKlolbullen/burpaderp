package com.victor.reconloop;

import burp.api.montoya.http.message.requests.HttpRequest;
import java.util.List;
import java.util.Set;

/** The same deterministic request construction is used by preview and live GraphQL execution. */
final class GraphQlRequestPlanner {
    static final int ALIASES = 100;

    static NativeRequestStep introspection(HttpRequest base) {
        return step(base, ApiSurfaceEngine.introspectionQuery(), "graphql-introspection",
                NativeRequestStep.Mutation.GRAPHQL_INTROSPECTION);
    }

    static List<NativeRequestStep> fuzz(HttpRequest base) {
        return List.of(
                step(base, GraphQlFuzzEngine.suggestionQuery(), "graphql-field-suggestions", NativeRequestStep.Mutation.GRAPHQL_SUGGESTIONS),
                step(base, GraphQlFuzzEngine.aliasQuery(ALIASES), "graphql-alias-amplification", NativeRequestStep.Mutation.GRAPHQL_ALIASES),
                step(base, GraphQlFuzzEngine.batchQuery(), "graphql-query-batching", NativeRequestStep.Mutation.GRAPHQL_BATCH));
    }

    private static NativeRequestStep step(HttpRequest base, String body, String probe, NativeRequestStep.Mutation mutation) {
        HttpRequest request = base.withMethod("POST").withUpdatedHeader("Content-Type", "application/json").withBody(body);
        return new NativeRequestStep(request, RequestPlan.create(request, probe, Set.of(
                RequestPolicy.Permission.UNSAFE_HTTP_METHOD, RequestPolicy.Permission.STATE_CHANGING)), mutation, List.of(), false);
    }
}
