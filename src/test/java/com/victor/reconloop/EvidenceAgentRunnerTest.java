package com.victor.reconloop;

import org.junit.Test;
import java.util.*;
import java.util.concurrent.atomic.*;
import static org.junit.Assert.*;

public class EvidenceAgentRunnerTest {
    static String result(String job, List<?> ids) {
        List<Object> reviews = new ArrayList<>();
        for (var id : ids) reviews.add(Map.of("candidate_id", id, "verdict", job.equals("report") ? "SUPPORTED" : "NEEDS_EVIDENCE",
                "reason", "Reachability and sanitization need manual verification."));
        return Json.write(Map.of("type", "result", "summary", job + " assessment (unverified).",
                "findings", job.equals("poc") ? List.of(AiAnalysisTest.finding("s1", "innerHTML")) : List.of(), "reviews", reviews));
    }
    static String valid(String prompt) {
        var data = Json.asObject(Json.parseStrict(prompt));
        return result((String) data.get("job"), Json.asArray(data.get("candidate_ids_to_review")));
    }
    static String tool(String name, Map<String, Object> args) { return Json.write(Map.of("type", "tool", "tool", name, "arguments", args)); }

    @Test public void allFiveJobsRunInOrderAndPreserveCandidateReviewDisagreement() {
        List<String> order = new ArrayList<>(); List<EvidenceAgentRunner.Usage> usage = new ArrayList<>();
        var runner = new EvidenceAgentRunner((credential, system, prompt, tokens) -> {
            var data = Json.asObject(Json.parseStrict(prompt)); order.add((String) data.get("job"));
            assertEquals(1024, tokens); assertTrue(prompt.contains("innerHTML"));
            if (order.size() > 1) assertTrue(prompt.contains("surface assessment"));
            return valid(prompt);
        });
        var plan = EvidenceAgentJobsTest.plan(0); var outcome = runner.run(plan, event -> {}, () -> false, usage::add);
        assertEquals(EvidenceAgentRunner.State.COMPLETED, outcome.state()); assertEquals(5, outcome.calls());
        assertEquals(List.of("surface", "poc", "boundaries", "review", "report"), order); assertEquals(5, usage.size());
        assertEquals("poc:1", outcome.results().get(1).candidates().getFirst().id());
        assertEquals("NEEDS_EVIDENCE", outcome.results().get(3).reviews().getFirst().verdict());
        assertEquals("SUPPORTED", outcome.results().get(4).reviews().getFirst().verdict());
        String render = EvidenceAgentRunner.render(plan, outcome);
        assertTrue(render.contains("CANDIDATE")); assertTrue(render.contains("NEEDS_EVIDENCE")); assertTrue(render.contains("SUPPORTED"));
        assertTrue(render.contains("OpenAI / account-model")); assertTrue(render.contains("skeptic-v1"));
        assertTrue(render.contains("No PoC was executed")); assertTrue(render.contains(AiAnalysis.sha256(plan.snapshot().sources().getFirst().text())));
    }

    @Test public void anAllowedToolAddsOneCallAndItsRedactedOutputBecomesJobContext() {
        AtomicInteger calls = new AtomicInteger();
        var runner = new EvidenceAgentRunner((c, s, p, t) -> {
            if (calls.incrementAndGet() == 1) return tool("search_sources", Map.of("query", "innerHTML"));
            if (calls.get() == 2) { assertTrue(p.contains("local_tool_results")); assertTrue(p.contains("Literal search")); assertTrue(p.contains("remaining_tool_calls\":0")); }
            return valid(p);
        });
        var outcome = runner.run(EvidenceAgentJobsTest.plan(1), event -> {}, () -> false);
        assertEquals(EvidenceAgentRunner.State.COMPLETED, outcome.state()); assertEquals(6, outcome.calls());
        assertEquals(1, outcome.tools().size()); assertEquals("search_sources", outcome.tools().getFirst().tool());
    }

    @Test public void unknownOrRoleForbiddenToolsFailTheJobAndSkipAllDependents() {
        for (String name : List.of("fetch_url", "shell", "read_file", "decode_excerpt")) {
            var runner = new EvidenceAgentRunner((c, s, p, t) -> tool(name, Map.of()));
            var outcome = runner.run(EvidenceAgentJobsTest.plan(1), event -> {}, () -> false);
            assertEquals(name, EvidenceAgentRunner.State.FAILED, outcome.state()); assertEquals(1, outcome.calls());
            assertTrue(outcome.tools().isEmpty()); assertTrue(outcome.results().subList(1, 5).stream().allMatch(r -> r.state() == EvidenceAgentRunner.State.SKIPPED));
        }
    }

    @Test public void repeatedToolRequestsCannotExceedTheActualProviderOrToolBudget() {
        var runner = new EvidenceAgentRunner((c, s, p, t) -> tool("source_index", Map.of()));
        var plan = EvidenceAgentJobsTest.plan(2); var outcome = runner.run(plan, event -> {}, () -> false);
        assertEquals(EvidenceAgentRunner.State.FAILED, outcome.state()); assertEquals(3, outcome.calls()); assertEquals(2, outcome.tools().size());
        assertTrue(outcome.calls() <= plan.maxCalls());
        var noTools = runner.run(EvidenceAgentJobsTest.plan(0), event -> {}, () -> false);
        assertEquals(1, noTools.calls()); assertTrue(noTools.tools().isEmpty());
    }

    @Test public void inventedSourceEvidenceCannotReachTheReviewerOrLead() {
        var runner = new EvidenceAgentRunner((c, s, p, t) -> {
            var data = Json.asObject(Json.parseStrict(p));
            if (data.get("job").equals("poc")) return Json.write(Map.of("type", "result", "summary", "Unfounded", "reviews", List.of(),
                    "findings", List.of(AiAnalysisTest.finding("s1", "fabricated snippet"))));
            return valid(p);
        });
        var outcome = runner.run(EvidenceAgentJobsTest.plan(0), event -> {}, () -> false);
        assertEquals(EvidenceAgentRunner.State.FAILED, outcome.state()); assertEquals(2, outcome.calls());
        assertTrue(outcome.results().get(1).candidates().isEmpty()); assertEquals(EvidenceAgentRunner.State.SKIPPED, outcome.results().getLast().state());
    }

    @Test public void reviewersCannotSilentlyDropOrInventCandidateIds() {
        for (List<?> ids : List.of(List.of(), List.of("not-a-candidate"), List.of("poc:1", "poc:1"))) {
            var runner = new EvidenceAgentRunner((c, s, p, t) -> {
                var data = Json.asObject(Json.parseStrict(p));
                return data.get("job").equals("review") ? result("review", ids) : valid(p);
            });
            var outcome = runner.run(EvidenceAgentJobsTest.plan(0), event -> {}, () -> false);
            assertEquals(EvidenceAgentRunner.State.FAILED, outcome.state()); assertEquals(4, outcome.calls());
            assertEquals(EvidenceAgentRunner.State.SKIPPED, outcome.results().getLast().state());
        }
    }

    @Test public void providerErrorsMalformedOutputAndOversizedResponsesStopThePipeline() {
        for (String raw : List.of("[HTTP 429] private body", "not JSON", "{\"type\":\"result\"}", "x".repeat(10_001),
                "{\"type\":\"result\",\"type\":\"tool\"}")) {
            var runner = new EvidenceAgentRunner((c, s, p, t) -> raw);
            var outcome = runner.run(EvidenceAgentJobsTest.plan(1), event -> {}, () -> false);
            assertEquals(EvidenceAgentRunner.State.FAILED, outcome.state()); assertEquals(1, outcome.calls());
            assertFalse(EvidenceAgentRunner.render(EvidenceAgentJobsTest.plan(1), outcome).contains("private body"));
        }
    }

    @Test public void derivedModelTextIsRedactedBeforeItIsForwardedToAnotherAgent() {
        AtomicInteger calls = new AtomicInteger();
        var runner = new EvidenceAgentRunner((c, s, p, t) -> {
            if (calls.incrementAndGet() == 1) return Json.write(Map.of("type", "result", "summary", "api_key=HIDDEN-DERIVED-SECRET", "findings", List.of(), "reviews", List.of()));
            assertFalse(p.contains("HIDDEN-DERIVED-SECRET")); return valid(p);
        });
        var plan = EvidenceAgentJobsTest.plan(0); var outcome = runner.run(plan, event -> {}, () -> false);
        assertEquals(EvidenceAgentRunner.State.COMPLETED, outcome.state());
        assertFalse(EvidenceAgentRunner.render(plan, outcome).contains("HIDDEN-DERIVED-SECRET"));
    }

    @Test public void cancellationBeforeAndDuringCallsPreventsTheNextDispatch() {
        var never = new EvidenceAgentRunner((c, s, p, t) -> { fail("Pre-cancelled plan cannot dispatch"); return null; });
        var before = never.run(EvidenceAgentJobsTest.plan(1), event -> {}, () -> true);
        assertEquals(EvidenceAgentRunner.State.CANCELLED, before.state()); assertEquals(0, before.calls());
        AtomicBoolean cancel = new AtomicBoolean();
        var during = new EvidenceAgentRunner((c, s, p, t) -> { cancel.set(true); return tool("source_index", Map.of()); });
        var outcome = during.run(EvidenceAgentJobsTest.plan(1), event -> {}, cancel::get);
        assertEquals(EvidenceAgentRunner.State.CANCELLED, outcome.state()); assertEquals(1, outcome.calls()); assertTrue(outcome.tools().isEmpty());
    }

    @Test public void interruptedCallsPreserveCancellationAndSkipTheOtherAgents() {
        var runner = new EvidenceAgentRunner((c, s, p, t) -> { throw new InterruptedException(); });
        try {
            var outcome = runner.run(EvidenceAgentJobsTest.plan(1), event -> {}, () -> false);
            assertEquals(EvidenceAgentRunner.State.CANCELLED, outcome.state()); assertTrue(Thread.currentThread().isInterrupted()); assertEquals(1, outcome.calls());
        } finally { Thread.interrupted(); }
    }

    @Test public void eventsDescribeJobStatesWithoutCopyingPromptOrModelSecrets() {
        List<EvidenceAgentRunner.Event> events = new ArrayList<>();
        var outcome = new EvidenceAgentRunner((c, s, p, t) -> valid(p)).run(EvidenceAgentJobsTest.plan(0), events::add, () -> false);
        assertEquals(5, events.stream().filter(e -> e.state() == EvidenceAgentRunner.State.QUEUED).count());
        assertEquals(5, events.stream().filter(e -> e.state() == EvidenceAgentRunner.State.COMPLETED).count());
        assertFalse(events.toString().contains("innerHTML")); assertFalse(events.toString().contains("FAKE-PRIVATE-KEY"));
        assertEquals(5, outcome.results().size());
    }
}
