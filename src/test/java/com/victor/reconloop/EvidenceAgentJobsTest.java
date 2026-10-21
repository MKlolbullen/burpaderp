package com.victor.reconloop;

import org.junit.Test;
import java.util.*;
import static org.junit.Assert.*;

public class EvidenceAgentJobsTest {
    static List<EvidenceAgentJobs.Binding> bindings(int tools) {
        return EvidenceAgentJobs.JOBS.stream().map(j -> new EvidenceAgentJobs.Binding(j.role(),
                new LlmClient.LlmCredential(j.role().defaultProvider(), "account-model", "FAKE-PRIVATE-KEY"), 1024, tools)).toList();
    }
    static EvidenceAgentJobs.Plan plan(int tools) { return EvidenceAgentJobs.plan(AiAnalysisTest.snapshot(), bindings(tools)); }

    @Test public void fiveJobsHaveExplicitDependenciesSkillsAndAllowedTools() {
        assertEquals(5, EvidenceAgentJobs.JOBS.size());
        assertEquals(List.of("surface", "poc", "boundaries", "review", "report"), EvidenceAgentJobs.JOBS.stream().map(EvidenceAgentJobs.Job::id).toList());
        String previous = "";
        for (var job : EvidenceAgentJobs.JOBS) {
            assertEquals(previous, job.dependsOn()); previous = job.id();
            assertFalse(job.skills().isEmpty()); assertFalse(job.tools().isEmpty());
            for (var skill : job.skills()) assertTrue(EvidenceAgentJobs.system(job).contains(skill.instructions()));
        }
        assertFalse(EvidenceAgentJobs.JOBS.getFirst().tools().contains(EvidenceAgentTools.Tool.DECODE_EXCERPT));
        assertTrue(EvidenceAgentJobs.JOBS.get(2).tools().contains(EvidenceAgentTools.Tool.DECODE_EXCERPT));
    }

    @Test public void previewExplainsSharingBudgetsAndProceduresWithoutKeys() {
        var plan = plan(1); assertEquals(10, plan.maxCalls()); assertEquals(10240, plan.maxOutputTokens());
        String preview = EvidenceAgentJobs.preview(plan);
        assertFalse(preview.contains("FAKE-PRIVATE-KEY")); assertTrue(preview.endsWith(plan.snapshot().prompt()));
        assertTrue(preview.contains("later messages also contain earlier job results"));
        for (var p : LlmProvider.values()) assertTrue(preview.contains(p.label()));
        assertFalse(plan.toString().contains("FAKE-PRIVATE-KEY"));
        assertFalse(new AgentTeam.AgentSpec(AgentRole.LEADER, LlmProvider.ANTHROPIC, "m", "FAKE-PRIVATE-KEY", ReasoningEffort.HIGH, 1000).toString().contains("FAKE-PRIVATE-KEY"));
    }

    @Test public void missingDuplicateOrInvalidAgentBindingsCannotDispatch() {
        var b = new ArrayList<>(bindings(1)); b.removeLast();
        assertThrows(IllegalArgumentException.class, () -> EvidenceAgentJobs.plan(AiAnalysisTest.snapshot(), b));
        b.add(b.getFirst()); assertThrows(IllegalArgumentException.class, () -> EvidenceAgentJobs.plan(AiAnalysisTest.snapshot(), b));
        assertThrows(IllegalArgumentException.class, () -> new EvidenceAgentJobs.Binding(AgentRole.RECON, bindings(1).getFirst().credential(), 100, 1));
        assertThrows(IllegalArgumentException.class, () -> new EvidenceAgentJobs.Binding(AgentRole.RECON, bindings(1).getFirst().credential(), 1024, 3));
    }

    @Test public void reviewerMustUseADifferentProviderFromBothDraftingRoles() {
        for (var role : List.of(AgentRole.EXPLOIT_DRAFTER, AgentRole.PAYLOAD_SPECIALIST)) {
            var b = new ArrayList<>(bindings(0));
            var source = b.stream().filter(v -> v.role() == role).findFirst().orElseThrow();
            int reviewer = 3; b.set(reviewer, new EvidenceAgentJobs.Binding(AgentRole.VERIFIER, source.credential(), 1024, 0));
            assertThrows(IllegalArgumentException.class, () -> EvidenceAgentJobs.plan(AiAnalysisTest.snapshot(), b));
        }
    }

    @Test public void teamContextRejectsLargeSelectionsRatherThanSilentlyTruncatingThem() {
        List<AiAnalysis.Source> sources = new ArrayList<>();
        for (int i = 1; i <= 3; i++) sources.add(new AiAnalysis.Source("s" + i, AiAnalysis.Kind.TEXT, "text", "x".repeat(40_000)));
        var snapshot = AiAnalysis.prepare(sources, "");
        assertThrows(IllegalArgumentException.class, () -> EvidenceAgentJobs.plan(snapshot, bindings(1)));
    }

    @Test public void rosterCollectionsAreImmutableAndIndependentRunsGetDifferentIds() {
        var bindings = new ArrayList<>(bindings(1)); var plan = EvidenceAgentJobs.plan(AiAnalysisTest.snapshot(), bindings); bindings.clear();
        assertEquals(5, plan.bindings().size()); assertThrows(UnsupportedOperationException.class, () -> plan.bindings().clear());
        assertNotEquals(plan.runId(), plan(1).runId());
    }
}
