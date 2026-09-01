package com.victor.reconloop;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.Objects;

/**
 * The one dispatch point for migrated target-directed requests.
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

    Result send(ScanRun run, RequestPolicy.PlannedRequest planned, HttpRequest request) {
        if (request == null || planned == null) {
            return Result.denied(RequestPolicy.Decision.deny(RequestPolicy.DecisionCode.INVALID_REQUEST,
                    "planned and concrete requests are required"));
        }
        try {
            if (!planned.matches(request.method(), request.url())) {
                return Result.denied(RequestPolicy.Decision.deny(RequestPolicy.DecisionCode.INVALID_REQUEST,
                        "concrete request does not match its approved plan"));
            }
        } catch (RuntimeException e) {
            return Result.denied(RequestPolicy.Decision.deny(RequestPolicy.DecisionCode.INVALID_REQUEST,
                    "could not inspect concrete request"));
        }

        RequestPolicy.Decision decision = policy.evaluate(run, planned);
        if (!decision.allowed()) return Result.denied(decision);
        if (!run.requestBudget().tryAcquire()) {
            return Result.denied(RequestPolicy.Decision.deny(RequestPolicy.DecisionCode.BUDGET_EXHAUSTED,
                    "run request budget is exhausted"));
        }
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
}
