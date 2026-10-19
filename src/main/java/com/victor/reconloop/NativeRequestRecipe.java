package com.victor.reconloop;

import burp.api.montoya.http.message.requests.HttpRequest;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.function.Supplier;

/** Lazy, network-free construction. Runtime templates deliberately have no executable binding. */
record NativeRequestRecipe(Supplier<HttpRequest> request, String probe,
                           Set<RequestPolicy.Permission> permissions, NativeRequestStep.Mutation mutation,
                           NativeRequestStep.Condition condition, String detail, boolean runtimeTemplate, NativeRequestStep.Constraints constraints) {
    NativeRequestRecipe(Supplier<HttpRequest> request, String probe, Set<RequestPolicy.Permission> permissions,
                        NativeRequestStep.Mutation mutation, NativeRequestStep.Condition condition, String detail, boolean runtimeTemplate) {
        this(request, probe, permissions, mutation, condition, detail, runtimeTemplate, null);
    }
    NativeRequestRecipe withConstraints(NativeRequestStep.Constraints value) {
        return new NativeRequestRecipe(request, probe, permissions, mutation, condition, detail, runtimeTemplate, value);
    }
    NativeRequestRecipe { permissions = Set.copyOf(permissions); }

    NativeRequestStep build() {
        HttpRequest concrete = request.get();
        Set<RequestPolicy.Permission> risks = mutationPermissions(concrete, permissions);
        RequestPolicy.PlannedRequest metadata = new RequestPolicy.PlannedRequest(concrete.method(), concrete.url(), probe, risks);
        return new NativeRequestStep(concrete, runtimeTemplate ? null : RequestPlan.bind(concrete, metadata), mutation,
                List.of(), condition, detail, runtimeTemplate ? metadata : null, constraints);
    }

    static Set<RequestPolicy.Permission> mutationPermissions(HttpRequest request, Set<RequestPolicy.Permission> risks) {
        EnumSet<RequestPolicy.Permission> result = EnumSet.noneOf(RequestPolicy.Permission.class);
        if (risks != null) result.addAll(risks);
        if (!ActiveTestEngine.isSafeMethod(request)) {
            result.add(RequestPolicy.Permission.UNSAFE_HTTP_METHOD);
            result.add(RequestPolicy.Permission.STATE_CHANGING);
        }
        return Set.copyOf(result);
    }
}
