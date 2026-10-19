package com.victor.reconloop;

import burp.api.montoya.http.message.requests.HttpRequest;
import java.util.List;

/** A concrete candidate or an explicitly non-executable runtime template; no response is synthesized. */
record NativeRequestStep(HttpRequest request, RequestPlan plan, Mutation mutation,
                         List<String> addedParameterNames, Condition condition, String detail,
                         RequestPolicy.PlannedRequest templateMetadata, Constraints constraints) {
    record Constraints(Object localKey, int localLimit, int minimumRemaining, Object requires, Object establishes) {}
    NativeRequestStep(HttpRequest request, RequestPlan plan, Mutation mutation, List<String> names,
                      Condition condition, String detail, RequestPolicy.PlannedRequest templateMetadata) {
        this(request, plan, mutation, names, condition, detail, templateMetadata, null);
    }
    NativeRequestStep withConstraints(Constraints value) {
        return new NativeRequestStep(request, plan, mutation, addedParameterNames, condition, detail, templateMetadata, value);
    }
    NativeRequestStep { addedParameterNames = List.copyOf(addedParameterNames); }
    NativeRequestStep(HttpRequest request, RequestPlan plan, Mutation mutation, List<String> names, boolean conditional) {
        this(request, plan, mutation, names, conditional ? Condition.PARAMETER_BASELINE : Condition.ALWAYS, "", null);
    }
    int addedParameters() { return addedParameterNames.size(); }
    boolean conditional() { return condition != Condition.ALWAYS; }
    boolean template() { return templateMetadata != null; }
    RequestPolicy.PlannedRequest metadata() { return template() ? templateMetadata : plan == null ? null : plan.policyRequest(); }
    enum Condition {
        ALWAYS(""),
        PARAMETER_BASELINE("requires a baseline response"),
        RESPONSE_BRANCH("requires a baseline response; later variants may be skipped after confirmation"),
        BASELINE_SUCCESS("requires a successful baseline response"),
        PRIOR_DISPATCH("requires the earlier baseline dispatch"),
        FALLBACK("attempted unless the earlier candidate matched"),
        RUNTIME_VALUE("requires a runtime callback value"),
        REDIRECT_RESPONSE("requires a redirect response; destination is unknown");
        final String description;
        Condition(String description) { this.description = description; }
    }
    enum Mutation {
        PARAMETER_BASELINE("Set method to GET; retain existing headers, body and parameters"),
        PARAMETER_CHUNK("Add URL parameters with generated canaries; retain existing values"),
        GRAPHQL_INTROSPECTION("Set POST and JSON content type; replace body with introspection query"),
        GRAPHQL_SUGGESTIONS("Set POST and JSON content type; replace body with invalid-field query"),
        GRAPHQL_ALIASES("Set POST and JSON content type; replace body with 100 field aliases"),
        GRAPHQL_BATCH("Set POST and JSON content type; replace body with query batch"),
        ACTIVE_VALUE("Replace one insertion point with a generated native probe"),
        ACTIVE_BASELINE("Replay the original insertion-point value as a baseline"),
        TIMING_BASELINE("Replay the original value for a timing baseline"),
        TIMING_PAYLOAD("Replace the insertion point with a time-delay payload"),
        HOST_HEADER("Replace X-Forwarded-Host with a runtime callback host"),
        CORS_ORIGIN("Replace Origin with a crafted origin"),
        AUTH_BURST("Replay the captured request unchanged as part of a six-request auth/lockout burst"),
        UPLOAD_FILENAME("Rename a multipart filename; retain the captured file bytes"),
        XML_BASELINE("Replay the captured XML body as a baseline"),
        XML_ENTITY("Replace the XML body with an external-entity probe"),
        CORPUS_VALUE("Replace one parameter with an encoded corpus entry"),
        JWT_BASELINE("Replay the captured JWT-bearing request unchanged"),
        JWT_NONE("Replace the captured JWT with an unsigned alg:none variant; retain its claims"),
        JWT_WEAK_SECRET("Replace the JWT with a re-signed token and marker claim if an offline weak secret is found"),
        ACCESS_CONTROL("Remove Cookie and Authorization; apply configured identity headers with values hidden"),
        TAKEOVER("Build a root GET for an enumerated host"),
        CRAWL_GET("Build an authenticated GET using captured origin headers"),
        CRAWL_REDIRECT("Build a GET only after the next redirect URL passes current scope and policy");

        final String description;
        Mutation(String description) { this.description = description; }
    }
}
