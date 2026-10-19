package com.victor.reconloop;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.Objects;

/**
 * The admission gate for every native target-directed Montoya dispatch.
 *
 * <p>The policy is evaluated before a request-budget token is acquired.  A second cancellation
 * check after acquisition prevents a request that raced with cancellation from being sent; consuming
 * a token in that rare race is intentional because budgets are never refunded after a dispatch race.
 */
final class ActiveRequestGateway {
    @FunctionalInterface
    interface Sender {
        HttpRequestResponse send(HttpRequest request) throws Exception;
    }

    record Result(RequestPolicy.Decision decision, HttpRequestResponse response, Exception error, boolean dispatched) {
        static Result denied(RequestPolicy.Decision decision) {
            return new Result(decision, null, null, false);
        }
    }

    private final RequestPolicy policy;
    private final Sender sender;

    ActiveRequestGateway(RequestPolicy policy, Sender sender) {
        this.policy = Objects.requireNonNull(policy, "policy");
        this.sender = Objects.requireNonNull(sender, "sender");
    }

    Result send(ScanRun run, RequestPlan plan, HttpRequest request) {
        if (plan == null || !plan.matches(request)) return invalidPlan();
        RequestPolicy.PlannedRequest planned = plan.policyRequest();
        RequestPolicy.Decision decision = admit(run, policy, planned);
        if (!decision.allowed()) return Result.denied(decision);
        // Montoya HttpRequest transformations are immutable. Check again after policy callbacks and
        // quota acquisition so a changed concrete message never inherits an earlier approval.
        if (!plan.matches(request)) return invalidPlan();
        if (!run.isRunning()) {
            RequestPolicy.DecisionCode code = run.isCancelled()
                    ? RequestPolicy.DecisionCode.CANCELLED : RequestPolicy.DecisionCode.RUN_NOT_ACTIVE;
            return Result.denied(RequestPolicy.Decision.deny(code, "run stopped before dispatch"));
        }
        try {
            return new Result(decision, sender.send(request), null, true);
        } catch (Exception e) {
            return new Result(decision, null, e, true);
        }
    }

    private static Result invalidPlan() {
        return Result.denied(RequestPolicy.Decision.deny(RequestPolicy.DecisionCode.INVALID_REQUEST,
                "concrete request bytes or transport destination do not match its plan"));
    }

    /** Shared by live dispatch and dry-run against an isolated quota snapshot. */
    static RequestPolicy.Decision admit(ScanRun run, RequestPolicy policy, RequestPolicy.PlannedRequest planned) {
        RequestPolicy.Decision decision = policy.evaluate(run, planned);
        if (!decision.allowed()) return decision;
        ScanRun.Allocation allocation = run.tryAcquire(planned);
        if (!allocation.allowed()) {
            RequestPolicy.DecisionCode code = switch (allocation.exhaustedQuota()) {
                case HOST -> RequestPolicy.DecisionCode.HOST_BUDGET_EXHAUSTED;
                case ENDPOINT -> RequestPolicy.DecisionCode.ENDPOINT_BUDGET_EXHAUSTED;
                case PROBE -> RequestPolicy.DecisionCode.PROBE_BUDGET_EXHAUSTED;
                case GLOBAL -> RequestPolicy.DecisionCode.BUDGET_EXHAUSTED;
            };
            return RequestPolicy.Decision.deny(code,
                    allocation.exhaustedQuota().name().toLowerCase(java.util.Locale.ROOT)
                            + " request budget exhausted for " + allocation.key()
                            + " (" + allocation.used() + "/" + allocation.limit() + ")");
        }
        return decision;
    }
}
