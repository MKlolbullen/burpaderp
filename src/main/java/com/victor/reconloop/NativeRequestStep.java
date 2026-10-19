package com.victor.reconloop;

import burp.api.montoya.http.message.requests.HttpRequest;
import java.util.List;

/** A concrete, deterministic step. Conditional steps require the earlier baseline response. */
record NativeRequestStep(HttpRequest request, RequestPlan plan, Mutation mutation,
                         List<String> addedParameterNames, boolean conditional) {
    NativeRequestStep { addedParameterNames = List.copyOf(addedParameterNames); }
    int addedParameters() { return addedParameterNames.size(); }
    enum Mutation {
        PARAMETER_BASELINE("Set method to GET; retain existing headers, body and parameters"),
        PARAMETER_CHUNK("Add URL parameters with generated canaries; retain existing values"),
        GRAPHQL_INTROSPECTION("Set POST and JSON content type; replace body with introspection query"),
        GRAPHQL_SUGGESTIONS("Set POST and JSON content type; replace body with invalid-field query"),
        GRAPHQL_ALIASES("Set POST and JSON content type; replace body with 100 field aliases"),
        GRAPHQL_BATCH("Set POST and JSON content type; replace body with query batch");

        final String description;
        Mutation(String description) { this.description = description; }
    }
}
