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
                  boolean truncated) {
        String render() {
            StringBuilder text = new StringBuilder("Dry run — no requests sent\n");
            text.append("Policy/quota estimate assuming active sending is enabled. Scope, permissions and budgets are checked again at dispatch.\n")
                    .append("Limits: global ").append(limits.global()).append(", host ").append(limits.perHost())
                    .append(", endpoint ").append(limits.perEndpoint()).append(", probe ").append(limits.perProbe()).append('\n')
                    .append("Admissible requests: up to ").append(admitted).append(" (including ")
                    .append(conditionalAdmitted).append(" conditional on a baseline response).\n")
                    .append("Original path, query values, headers and body are hidden. No DNS lookup or Collaborator allocation.\n\n");
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
        List<Row> rows = new ArrayList<>();
        var iterator = steps.iterator();
        int admitted = 0, conditional = 0;
        boolean baselineAdmitted = false;
        while (rows.size() < MAX_STEPS && iterator.hasNext()) {
            NativeRequestStep step = iterator.next();
            RequestPlan plan = step.plan();
            RequestPolicy.PlannedRequest request = plan == null ? null : plan.policyRequest();
            RequestPolicy.Decision decision;
            if (step.conditional() && !baselineAdmitted) {
                decision = RequestPolicy.Decision.deny(RequestPolicy.DecisionCode.PREREQUISITE_DENIED, "baseline denied");
            } else if (plan == null || !plan.matches(step.request())) {
                decision = RequestPolicy.Decision.deny(RequestPolicy.DecisionCode.INVALID_REQUEST, "invalid plan");
            } else {
                decision = ActiveRequestGateway.admit(shadow, policy, request);
            }
            if (step.mutation() == NativeRequestStep.Mutation.PARAMETER_BASELINE) baselineAdmitted = decision.allowed();
            if (decision.allowed()) { admitted++; if (step.conditional()) conditional++; }
            rows.add(new Row(request == null ? "?" : request.method(), destination(request),
                    request == null ? "?" : request.probeId(), step.mutation().description
                    + (step.addedParameters() == 0 ? "" : " (" + step.addedParameters() + " added: " + parameterNames(step.addedParameterNames()) + ")"),
                    step.conditional(), decision.code(), decision.missingPermissions().stream().map(Enum::name).sorted()
                    .collect(java.util.stream.Collectors.joining(", "))));
        }
        return new Report(List.copyOf(rows), run.requestLimits(), admitted, conditional, iterator.hasNext());
    }

    private static String parameterNames(List<String> names) {
        return names.stream().map(name -> name.codePoints().limit(80)
                .map(c -> Character.isISOControl(c) ? '?' : c)
                .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append).toString())
                .collect(java.util.stream.Collectors.joining(", "));
    }

    private static String destination(RequestPolicy.PlannedRequest request) {
        try {
            URI uri = URI.create(request.url());
            return uri.getScheme() + "://" + uri.getHost() + (uri.getPort() == -1 ? "" : ":" + uri.getPort()) + "/[path hidden]";
        } catch (RuntimeException e) { return "[invalid destination]"; }
    }
}
