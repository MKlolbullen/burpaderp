package com.victor.reconloop;

import java.util.*;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

/** Bounded JSON tool loop and dependency execution. Has no target transport or issue publisher. */
final class EvidenceAgentRunner {
    enum State { QUEUED, RUNNING, LOCAL_TOOL, COMPLETED, FAILED, CANCELLED, SKIPPED }
    record Event(String jobId, AgentRole role, LlmProvider provider, String model, State state,
                 int calls, int tools, String detail) {}
    record Review(String candidateId, String verdict, String reason) {}
    record Candidate(String id, AiAnalysis.Finding finding) {}
    record ToolTrace(String jobId, String tool, String result) {}
    record Usage(String jobId, LlmProvider provider, String model, int call, long input, long output, AiFeed.Outcome outcome) {}
    record Result(EvidenceAgentJobs.Job job, State state, String summary, AiAnalysis.Report findings,
                  List<Candidate> candidates, List<Review> reviews, int calls, int tools,
                  long estimatedInput, long estimatedOutput, String history, String error) {
        Result { candidates = List.copyOf(candidates); reviews = List.copyOf(reviews); }
    }
    record Outcome(String runId, State state, List<Result> results, List<ToolTrace> tools) {
        Outcome { results = List.copyOf(results); tools = List.copyOf(tools); }
        int calls() { return results.stream().mapToInt(Result::calls).sum(); }
        long estimatedTokens() { return results.stream().mapToLong(r -> r.estimatedInput() + r.estimatedOutput()).sum(); }
    }
    @FunctionalInterface interface Completion {
        String complete(LlmClient.LlmCredential credential, String system, String prompt, int maxOutputTokens) throws Exception;
    }
    private static final class Validation extends IllegalArgumentException {
        Validation(String message) { super(message); }
    }
    private final Completion completion;
    EvidenceAgentRunner(Completion completion) { this.completion = Objects.requireNonNull(completion); }

    Outcome run(EvidenceAgentJobs.Plan plan, Consumer<Event> events, BooleanSupplier cancelled) {
        return run(plan, events, cancelled, usage -> {});
    }

    Outcome run(EvidenceAgentJobs.Plan plan, Consumer<Event> events, BooleanSupplier cancelled, Consumer<Usage> usage) {
        List<Result> results = new ArrayList<>(); List<ToolTrace> traces = new ArrayList<>();
        Map<String, Candidate> candidates = new LinkedHashMap<>(); State state = State.COMPLETED;
        for (var job : EvidenceAgentJobs.JOBS) emit(plan, job, State.QUEUED, 0, 0, "Waiting for dependency", events);
        for (var job : EvidenceAgentJobs.JOBS) {
            if (state != State.COMPLETED) {
                var skipped = empty(job, State.SKIPPED, "Dependency did not complete."); results.add(skipped);
                emit(plan, job, State.SKIPPED, 0, 0, skipped.error(), events); continue;
            }
            Result result;
            if (cancelled(cancelled)) result = empty(job, State.CANCELLED, "Cancelled before job dispatch.");
            else result = runJob(plan, job, results, candidates, traces, events, cancelled, usage);
            results.add(result);
            emit(plan, job, result.state(), result.calls(), result.tools(),
                    result.error() == null ? result.candidates().size() + " candidate(s); " + result.reviews().size() + " review(s)" : result.error(), events);
            if (result.state() != State.COMPLETED) state = result.state();
            else for (var candidate : result.candidates()) candidates.put(candidate.id(), candidate);
        }
        return new Outcome(plan.runId(), state, results, traces);
    }

    private Result runJob(EvidenceAgentJobs.Plan plan, EvidenceAgentJobs.Job job, List<Result> prior,
                          Map<String, Candidate> known, List<ToolTrace> traces, Consumer<Event> events,
                          BooleanSupplier cancel, Consumer<Usage> usage) {
        var binding = plan.binding(job.role()); int calls = 0, tools = 0; long in = 0, out = 0;
        List<Object> localResults = new ArrayList<>();
        try {
            emit(plan, job, State.RUNNING, 0, 0, "Reviewing selected evidence", events);
            for (int turn = 0; turn <= binding.toolCalls(); turn++) {
                if (cancelled(cancel)) return failed(job, State.CANCELLED, calls, tools, in, out, "Cancelled.");
                String prompt = prompt(plan, job, prior, known, localResults, binding.toolCalls() - tools);
                if (prompt.length() > 180_000) throw new Validation("Derived context exceeded 180,000 characters; reduce the selected evidence.");
                String system = EvidenceAgentJobs.system(job);
                calls++; long callInput = AgentActivity.estimateTokens(system + prompt); in += callInput;
                String raw = completion.complete(binding.credential(), system, prompt, binding.outputTokens());
                long callOutput = AgentActivity.estimateTokens(raw); out += callOutput;
                usage.accept(new Usage(job.id(), binding.credential().provider(), binding.credential().model(), calls,
                        callInput, callOutput, AiFeed.outcomeFor(raw)));
                if (cancelled(cancel)) return failed(job, State.CANCELLED, calls, tools, in, out, "Cancelled.");
                if (raw == null || raw.length() > 10_000) throw new Validation("Missing or oversized agent response (maximum 10,000 characters).");
                if (AiFeed.outcomeFor(raw) == AiFeed.Outcome.ERROR) throw new Validation("Provider did not return a complete result.");
                Map<String, Object> parsed = Json.asObject(sanitize(Json.parseStrict(raw)));
                if (parsed == null) throw new Validation("Agent response must be a JSON object.");
                String type = string(parsed, "type", 10);
                if (type.equals("tool")) {
                    keys(parsed, "type", "tool", "arguments");
                    if (tools >= binding.toolCalls()) throw new Validation("Agent exceeded its local tool-call limit.");
                    String name = string(parsed, "tool", 40);
                    String text;
                    try { text = EvidenceAgentTools.execute(plan.snapshot(), job.tools(), name, Json.asObject(parsed.get("arguments"))); }
                    catch (IllegalArgumentException e) { throw new Validation("Local tool request rejected: role allowlist, arguments or source checks failed."); }
                    tools++; traces.add(new ToolTrace(job.id(), name, text));
                    localResults.add(Map.of("tool", name, "result", text));
                    emit(plan, job, State.LOCAL_TOOL, calls, tools, name, events);
                } else if (type.equals("result")) {
                    return result(plan, job, parsed, known, calls, tools, in, out);
                } else throw new Validation("Unknown agent response type.");
            }
            throw new Validation("Agent did not finish within its call budget.");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt(); return failed(job, State.CANCELLED, calls, tools, in, out, "Cancelled.");
        } catch (Validation e) {
            return failed(job, State.FAILED, calls, tools, in, out, e.getMessage());
        } catch (IllegalArgumentException e) {
            // Parser exceptions can include input fragments; do not surface their details.
            return failed(job, State.FAILED, calls, tools, in, out, "Invalid response/tool request or context limit. No dependent jobs were dispatched.");
        } catch (Exception e) {
            return failed(job, State.FAILED, calls, tools, in, out, "Agent call failed (" + e.getClass().getSimpleName() + ").");
        }
    }

    private static Result result(EvidenceAgentJobs.Plan plan, EvidenceAgentJobs.Job job, Map<String, Object> root,
                                 Map<String, Candidate> known, int calls, int tools, long in, long out) {
        keys(root, "type", "summary", "findings", "reviews"); String summary = string(root, "summary", 2000);
        var findings = Json.asArray(root.get("findings")); var reviews = Json.asArray(root.get("reviews"));
        if (findings == null || reviews == null || findings.size() > 5 || reviews.size() > 15)
            throw new Validation("Invalid result arrays.");
        if (EvidenceAgentJobs.reviewer(job) ? !findings.isEmpty() : !reviews.isEmpty())
            throw new Validation("Result does not match the agent's job.");
        for (var value : findings) keys(Json.asObject(value), "source_id", "evidence", "title", "severity", "confidence",
                "vuln_class", "description", "poc", "assumptions", "remediation");
        var report = AiAnalysis.parse(Json.write(Map.of("findings", findings)), plan.snapshot());
        if (report.error() != null || report.rejected() != 0) throw new Validation("Unanchored or invalid finding.");
        List<Review> judgments = new ArrayList<>(); Set<String> reviewed = new HashSet<>();
        for (var value : reviews) {
            var r = Json.asObject(value); keys(r, "candidate_id", "verdict", "reason");
            String id = string(r, "candidate_id", 30), verdict = string(r, "verdict", 20), reason = string(r, "reason", 400);
            if (!known.containsKey(id) || !reviewed.add(id) || !Set.of("SUPPORTED", "NEEDS_EVIDENCE", "REJECTED").contains(verdict))
                throw new Validation("Invalid candidate review.");
            judgments.add(new Review(id, verdict, reason));
        }
        if (EvidenceAgentJobs.reviewer(job) && !reviewed.equals(known.keySet())) throw new Validation("Incomplete candidate coverage.");
        List<Candidate> candidates = new ArrayList<>(); int index = 1;
        for (var finding : report.findings()) candidates.add(new Candidate(job.id() + ":" + index++, finding));
        Map<String, Object> history = new LinkedHashMap<>(); history.put("job", job.id()); history.put("summary", summary);
        List<Object> identified = new ArrayList<>();
        for (int i = 0; i < candidates.size(); i++) identified.add(Map.of("candidate_id", candidates.get(i).id(), "finding", findings.get(i)));
        history.put("candidates", identified); history.put("reviews", reviews);
        String canonical = Json.write(history);
        if (canonical.length() > 12_000) throw new Validation("Derived result too large.");
        return new Result(job, State.COMPLETED, summary, report, candidates, judgments, calls, tools, in, out, canonical, null);
    }

    static String prompt(EvidenceAgentJobs.Plan plan, EvidenceAgentJobs.Job job, List<Result> prior,
                         Map<String, Candidate> known, List<Object> tools, int remaining) {
        Map<String, Object> data = new LinkedHashMap<>(); data.put("run_id", plan.runId()); data.put("job", job.id());
        data.put("evidence", Json.parseStrict(plan.snapshot().prompt()));
        data.put("prior_jobs", prior.stream().map(r -> Json.parseStrict(r.history())).toList());
        data.put("candidate_ids_to_review", EvidenceAgentJobs.reviewer(job) ? new ArrayList<>(known.keySet()) : List.of());
        data.put("local_tool_results", tools); data.put("remaining_tool_calls", remaining);
        return Json.write(data);
    }

    private static Object sanitize(Object value) {
        if (value instanceof String s) return AiAnalysis.redactDerived(s);
        if (value instanceof List<?> list) return list.stream().map(EvidenceAgentRunner::sanitize).toList();
        if (value instanceof Map<?, ?> map) {
            Map<String, Object> clean = new LinkedHashMap<>(); map.forEach((key, item) -> clean.put((String) key, sanitize(item))); return clean;
        }
        return value;
    }
    private static String string(Map<String, Object> data, String key, int max) {
        if (data == null || !(data.get(key) instanceof String s) || s.isBlank() || s.length() > max)
            throw new Validation("Invalid result string.");
        return s;
    }
    private static void keys(Map<String, Object> data, String... keys) {
        if (data == null || !data.keySet().equals(Set.of(keys))) throw new Validation("Unexpected response fields.");
    }
    private static boolean cancelled(BooleanSupplier cancelled) { return Thread.currentThread().isInterrupted() || cancelled.getAsBoolean(); }
    private static Result empty(EvidenceAgentJobs.Job job, State state, String error) { return failed(job, state, 0, 0, 0, 0, error); }
    private static Result failed(EvidenceAgentJobs.Job job, State state, int calls, int tools, long in, long out, String error) {
        return new Result(job, state, "", null, List.of(), List.of(), calls, tools, in, out, "{}", error);
    }
    private static void emit(EvidenceAgentJobs.Plan plan, EvidenceAgentJobs.Job job, State state, int calls, int tools, String detail, Consumer<Event> events) {
        var credential = plan.binding(job.role()).credential();
        events.accept(new Event(job.id(), job.role(), credential.provider(), credential.model(), state, calls, tools, detail));
    }

    static String render(EvidenceAgentJobs.Plan plan, Outcome outcome) {
        StringBuilder text = new StringBuilder("Run " + outcome.runId() + " · " + outcome.state() + "\nProvider calls: "
                + outcome.calls() + " / " + plan.maxCalls() + "; estimated tokens: ~" + outcome.estimatedTokens()
                + " (text-length estimate, not billed usage).\nAll candidates remain unverified. No PoC was executed.\n");
        for (var result : outcome.results()) {
            text.append("\n=== ").append(result.job().id()).append(" · ").append(result.job().role().title()).append(" · ").append(result.state()).append(" ===\n");
            var credential = plan.binding(result.job().role()).credential();
            text.append("Provider / configured model: ").append(credential.provider().label()).append(" / ").append(credential.model())
                    .append("\nSkills: ").append(result.job().skills().stream().map(AgentSkill::id).toList())
                    .append("\nCalls: ").append(result.calls()).append("; local tools: ").append(result.tools()).append('\n');
            if (result.error() != null) { text.append(result.error()).append('\n'); continue; }
            text.append("Model assessment (unverified): ").append(result.summary()).append('\n');
            if (!result.candidates().isEmpty()) text.append("Candidate IDs: ").append(result.candidates().stream().map(Candidate::id).toList()).append('\n');
            text.append(AiAnalysis.render(result.findings(), plan.snapshot()));
            for (var review : result.reviews()) text.append("\n").append(review.candidateId()).append(" · ").append(review.verdict()).append(" — ").append(review.reason()).append('\n');
        }
        text.append("\nLOCAL TOOL TRACE (untrusted derived text; no execution):\n");
        for (var trace : outcome.tools()) text.append('\n').append(trace.jobId()).append(" / ").append(trace.tool()).append('\n').append(trace.result()).append('\n');
        return text.toString();
    }
}
