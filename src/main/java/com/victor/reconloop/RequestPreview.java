package com.victor.reconloop;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;

/** Network-free, bounded simulation. Only redacted display data escapes this class. */
final class RequestPreview {
    static final int MAX_STEPS = 500;
    record Row(String method, String destination, String probe, String mutation, boolean conditional,
               RequestPolicy.DecisionCode decision, String missingPermissions) {}
    record Report(List<Row> rows, ScanRun.RequestLimits limits, int admitted, int conditionalAdmitted,
                  boolean truncated, boolean branchDependent, int runtimeTemplates, int alreadyUsed) {
        String render() {
            StringBuilder text = new StringBuilder("Dry run — no requests sent\n");
            text.append("Policy/quota estimate assuming the selected workflow is enabled. Scope, permissions and budgets are checked again at dispatch.\nDNS answers and numeric-service binding are not verified by this preview; they can still deny dispatch.\n")
                    .append("Limits: global ").append(limits.global()).append(", host ").append(limits.perHost())
                    .append(", endpoint ").append(limits.perEndpoint()).append(", probe ").append(limits.perProbe()).append('\n')
                    .append("Already used: ").append(alreadyUsed).append("; global remaining: ").append(Math.max(0, limits.global() - alreadyUsed)).append('\n')
                    .append(branchDependent ? "Concrete candidates fitting this ordered scenario: " : "Admissible requests: up to ")
                    .append(admitted).append(" (including ").append(conditionalAdmitted).append(" conditional).\n");
            if (branchDependent) text.append("Response branches and early matches change which candidates run; this scenario count is not a worst-case bound. The configured global limit is the hard dispatch ceiling.\n");
            if (rows.stream().anyMatch(row -> row.probe().equals("discovery-crawl")))
                text.append("Future crawl discoveries are not included in this scenario, even when redirect following is disabled.\n");
            if (runtimeTemplates > 0) text.append(runtimeTemplates).append(" runtime templates are not executable plans and are excluded from quota simulation. Their exact scope and budget admission remain pending.\n");
            text.append("Original path, query values, header/body values and uploaded filenames are hidden. No DNS lookup or Collaborator allocation.\n\n");
            if (rows.isEmpty()) text.append("No candidate requests in the current selection.\n");
            for (int i = 0; i < rows.size(); i++) {
                Row row = rows.get(i);
                text.append(i + 1).append(". ").append(row.method()).append(' ').append(row.destination())
                        .append(" | ").append(row.probe()).append(" | ").append(row.decision());
                if (!row.missingPermissions().isEmpty()) text.append(" ").append(row.missingPermissions());
                text.append(row.conditional() ? " | conditional" : "").append('\n')
                        .append("   ").append(row.mutation()).append('\n');
            }
            if (truncated) text.append("\nPreview limited to the first ").append(MAX_STEPS)
                    .append(" steps. Counts describe this prefix only; remaining steps are not estimated.\n");
            return text.toString();
        }
    }

    static Report inspect(ScanRun run, RequestPolicy policy, Iterable<NativeRequestStep> steps) {
        ScanRun shadow = run.previewCopy();
        int alreadyUsed = shadow.requestBudget().used();
        List<Row> rows = new ArrayList<>();
        var iterator = steps.iterator();
        java.util.Map<Object, RequestBudget> localBudgets = new java.util.HashMap<>();
        java.util.Set<Object> established = new java.util.HashSet<>();
        int admitted = 0, conditional = 0;
        boolean baselineAdmitted = false, branchDependent = false;
        int runtimeTemplates = 0;
        while (rows.size() < MAX_STEPS && iterator.hasNext()) {
            NativeRequestStep step = iterator.next();
            RequestPlan plan = step.plan();
            RequestPolicy.PlannedRequest request = step.metadata();
            if (step.template()) runtimeTemplates++;
            branchDependent |= step.template() || step.mutation() == NativeRequestStep.Mutation.CRAWL_GET
                    || (step.conditional() && step.condition() != NativeRequestStep.Condition.PARAMETER_BASELINE);
            NativeRequestStep.Constraints constraints = step.constraints();
            RequestBudget local = constraints == null || constraints.localKey() == null ? null
                    : localBudgets.computeIfAbsent(constraints.localKey(), key -> new RequestBudget(constraints.localLimit()));
            int minimum = constraints == null ? 1 : Math.max(1, constraints.minimumRemaining());
            RequestPolicy.Decision decision;
            if (constraints != null && constraints.requires() != null && !established.contains(constraints.requires())) {
                decision = RequestPolicy.Decision.deny(RequestPolicy.DecisionCode.PREREQUISITE_DENIED, "earlier admission required");
            } else if (local != null && local.remaining() < minimum) {
                decision = RequestPolicy.Decision.deny(RequestPolicy.DecisionCode.LOCAL_BUDGET_EXHAUSTED, "local category cap exhausted");
            } else if (minimum > 1 && shadow.requestBudget().remaining() < minimum) {
                decision = RequestPolicy.Decision.deny(RequestPolicy.DecisionCode.BUDGET_EXHAUSTED, "pair requires two tokens");
            } else if (step.condition() == NativeRequestStep.Condition.PARAMETER_BASELINE && !baselineAdmitted) {
                decision = RequestPolicy.Decision.deny(RequestPolicy.DecisionCode.PREREQUISITE_DENIED, "baseline denied");
            } else if (step.template()) {
                decision = policy.assessTemplate(shadow, request);
                if (decision.allowed()) decision = RequestPolicy.Decision.deny(
                        step.mutation() == NativeRequestStep.Mutation.CRAWL_REDIRECT
                                ? RequestPolicy.DecisionCode.PENDING_DESTINATION : RequestPolicy.DecisionCode.PENDING_BINDING,
                        "runtime materialization required");
            } else if (plan == null || !plan.matches(step.request())) {
                decision = RequestPolicy.Decision.deny(RequestPolicy.DecisionCode.INVALID_REQUEST, "invalid plan");
            } else {
                decision = ActiveRequestGateway.admit(shadow, policy, request);
            }
            if (step.mutation() == NativeRequestStep.Mutation.PARAMETER_BASELINE) baselineAdmitted = decision.allowed();
            if (decision.allowed()) {
                admitted++;
                if (step.conditional()) conditional++;
                if (local != null) local.tryAcquire();
                if (constraints != null && constraints.establishes() != null) established.add(constraints.establishes());
            }
            rows.add(new Row(request == null ? "?" : request.method(), step.mutation() == NativeRequestStep.Mutation.CRAWL_REDIRECT
                            ? "[response-dependent destination]" : destination(request),
                    request == null ? "?" : request.probeId(), step.mutation().description
                    + (step.addedParameters() == 0 ? "" : " (" + step.addedParameters() + " added: " + parameterNames(step.addedParameterNames()) + ")")
                    + (step.detail().isBlank() ? "" : "; " + displayText(step.detail(), 240))
                    + (step.conditional() ? "; " + step.condition().description : ""),
                    step.conditional(), decision.code(), decision.missingPermissions().stream().map(Enum::name).sorted()
                    .collect(java.util.stream.Collectors.joining(", "))));
        }
        return new Report(List.copyOf(rows), run.requestLimits(), admitted, conditional, iterator.hasNext(), branchDependent, runtimeTemplates, alreadyUsed);
    }

    private static String parameterNames(List<String> names) {
        return names.stream().map(name -> displayText(name, 80)).collect(java.util.stream.Collectors.joining(", "));
    }

    private static String displayText(String value, int limit) {
        String result = value.codePoints().limit(limit)
                .map(c -> Character.isISOControl(c) || Character.getType(c) == Character.FORMAT || c == 0x2028 || c == 0x2029 ? '?' : c)
                .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append).toString();
        return value.codePointCount(0, value.length()) > limit ? result + "…" : result;
    }

    private static String destination(RequestPolicy.PlannedRequest request) {
        try {
            URI uri = URI.create(request.url());
            return uri.getScheme() + "://" + uri.getHost() + (uri.getPort() == -1 ? "" : ":" + uri.getPort()) + "/[path hidden]";
        } catch (RuntimeException e) { return "[invalid destination]"; }
    }
}
