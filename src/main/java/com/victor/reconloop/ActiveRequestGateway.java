package com.victor.reconloop;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.Objects;
import java.util.function.LongSupplier;

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

    /** Production native transport prepares a numeric destination before any token is reserved. */
    interface PreparedSender extends Sender {
        Dispatch prepare(HttpRequest request) throws Exception;
        @Override default HttpRequestResponse send(HttpRequest request) {
            throw new IllegalStateException("destination preparation is mandatory");
        }
    }
    @FunctionalInterface interface Dispatch { HttpRequestResponse send() throws Exception; }

    record Result(RequestPolicy.Decision decision, HttpRequestResponse response, Exception error, boolean dispatched,
                  FindingEvidence.Exchange exchange, long transportElapsedNanos) {
        Result(RequestPolicy.Decision decision, HttpRequestResponse response, Exception error, boolean dispatched) {
            this(decision, response, error, dispatched, null, -1);
        }
        Result(RequestPolicy.Decision decision, HttpRequestResponse response, Exception error, boolean dispatched,
               FindingEvidence.Exchange exchange) {
            this(decision, response, error, dispatched, exchange, exchange == null ? -1 : exchange.transportElapsedNanos());
        }
        static Result denied(RequestPolicy.Decision decision) {
            return new Result(decision, null, null, false);
        }
    }

    private final RequestPolicy policy;
    private final Sender sender;
    private final LongSupplier nanoTime;

    ActiveRequestGateway(RequestPolicy policy, Sender sender) {
        this(policy, sender, System::nanoTime);
    }

    /** Package-local monotonic clock seam for deterministic timing integration tests. */
    ActiveRequestGateway(RequestPolicy policy, Sender sender, LongSupplier nanoTime) {
        this.policy = Objects.requireNonNull(policy, "policy");
        this.sender = Objects.requireNonNull(sender, "sender");
        this.nanoTime = Objects.requireNonNull(nanoTime, "nanoTime");
    }

    Result send(ScanRun run, RequestPlan plan, HttpRequest request) {
        long start = nanoTime.getAsLong();
        Result result = dispatch(run, plan, request);
        if (run != null) run.record(plan, result);
        if (run == null || plan == null || plan.policyRequest() == null || request == null) return result;
        // Evidence collection must not change a completed dispatch or policy decision.
        try {
            return new Result(result.decision(), result.response(), result.error(), result.dispatched(),
                    EvidenceCapture.exchange(run, plan, request, result, nanoTime.getAsLong() - start), result.transportElapsedNanos());
        } catch (RuntimeException unavailable) { return result; }
    }

    private Result dispatch(ScanRun run, RequestPlan plan, HttpRequest request) {
        if (run != null && !run.awaitReady()) return Result.denied(RequestPolicy.Decision.deny(
                run.isCancelled() ? RequestPolicy.DecisionCode.CANCELLED : RequestPolicy.DecisionCode.RUN_NOT_ACTIVE, "run stopped"));
        if (plan == null || !plan.matches(request)) return invalidPlan();
        if (Thread.currentThread().isInterrupted()) return Result.denied(RequestPolicy.Decision.deny(
                RequestPolicy.DecisionCode.CANCELLED, "worker interrupted before destination preparation"));
        RequestPolicy.PlannedRequest planned = plan.policyRequest();
        Dispatch dispatch = null;
        if (sender instanceof PreparedSender prepared) {
            RequestPolicy.Decision initial = policy.evaluate(run, planned);
            if (!initial.allowed()) return Result.denied(initial);
            if (run.requestBudget().exhausted()) return Result.denied(admit(run, policy, planned));
            try {
                dispatch = prepared.prepare(request);
                if (dispatch == null) throw new IllegalStateException("missing prepared dispatch");
            } catch (DestinationGuard.Rejected e) {
                return Result.denied(RequestPolicy.Decision.deny(e.code, e.getMessage()));
            } catch (Exception e) {
                return Result.denied(RequestPolicy.Decision.deny(RequestPolicy.DecisionCode.DESTINATION_BINDING_FAILED,
                        "destination preparation failed closed"));
            }
        }
        if (Thread.currentThread().isInterrupted()) return Result.denied(RequestPolicy.Decision.deny(
                RequestPolicy.DecisionCode.CANCELLED, "worker interrupted before admission"));
        if (run != null && !run.awaitReady()) return Result.denied(RequestPolicy.Decision.deny(
                RequestPolicy.DecisionCode.CANCELLED, "run stopped before admission"));
        RequestPolicy.Decision decision = admit(run, policy, planned);
        if (!decision.allowed()) return Result.denied(decision);
        // Montoya HttpRequest transformations are immutable. Check again after policy callbacks and
        // quota acquisition so a changed concrete message never inherits an earlier approval.
        if (!plan.matches(request)) return invalidPlan();
        if (!run.awaitReady()) {
            RequestPolicy.DecisionCode code = run.isCancelled()
                    ? RequestPolicy.DecisionCode.CANCELLED : RequestPolicy.DecisionCode.RUN_NOT_ACTIVE;
            return Result.denied(RequestPolicy.Decision.deny(code, "run stopped before dispatch"));
        }
        // Measure only the admitted transport invocation, excluding gateway DNS/admission and engine pacing.
        // This is API elapsed time, not a wire-level RTT or proof of server execution.
        run.dispatching(plan);
        long start = nanoTime.getAsLong();
        try {
            HttpRequestResponse response = dispatch == null ? sender.send(request) : dispatch.send();
            return new Result(decision, response, null, true, null, Math.max(0, nanoTime.getAsLong() - start));
        } catch (Exception e) {
            return new Result(decision, null, e, true, null, Math.max(0, nanoTime.getAsLong() - start));
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
            if (!run.isRunning()) return RequestPolicy.Decision.deny(run.isCancelled()
                    ? RequestPolicy.DecisionCode.CANCELLED : RequestPolicy.DecisionCode.RUN_NOT_ACTIVE, "run stopped during admission");
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
