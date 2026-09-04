package com.victor.reconloop;

import org.junit.Test;

import java.util.List;

import static org.junit.Assert.*;

public class AgentOrchestratorTest {

    private static AgentTeam.AgentSpec spec(AgentRole role, LlmProvider provider, ReasoningEffort effort, int budget) {
        return new AgentTeam.AgentSpec(role, provider, null, "key", effort, budget);
    }

    private static AgentOrchestrator.RoundResult round(AgentRole role, LlmProvider provider, String output) {
        return new AgentOrchestrator.RoundResult(role, provider, output);
    }

    // ---- workerOrder ----

    @Test
    public void workerOrderExcludesTheLeaderAndSortsByRolePriority() {
        AgentTeam.AgentSpec leader = spec(AgentRole.LEADER, LlmProvider.ANTHROPIC, ReasoningEffort.MAX, 8000);
        AgentTeam.AgentSpec verifier = spec(AgentRole.VERIFIER, LlmProvider.XAI, ReasoningEffort.HIGH, 6000);
        AgentTeam.AgentSpec recon = spec(AgentRole.RECON, LlmProvider.GEMINI, ReasoningEffort.LOW, 2000);
        AgentTeam.AgentSpec drafter = spec(AgentRole.EXPLOIT_DRAFTER, LlmProvider.OPENAI, ReasoningEffort.HIGH, 6000);

        AgentTeam.Plan plan = AgentTeam.plan(List.of(verifier, leader, drafter, recon));
        List<AgentTeam.AgentSpec> workers = AgentOrchestrator.workerOrder(plan);

        assertFalse(workers.contains(leader));
        // Priority: recon (0) -> drafter (1) -> verifier (3).
        assertEquals(List.of(recon, drafter, verifier), workers);
    }

    @Test
    public void aSoleLeaderHasNoWorkerRounds() {
        AgentTeam.AgentSpec leader = spec(AgentRole.LEADER, LlmProvider.ANTHROPIC, ReasoningEffort.HIGH, 8000);
        assertTrue(AgentOrchestrator.workerOrder(AgentTeam.plan(List.of(leader))).isEmpty());
        assertTrue(AgentOrchestrator.workerOrder(AgentTeam.plan(List.of())).isEmpty());
        assertTrue(AgentOrchestrator.workerOrder(null).isEmpty());
    }

    @Test
    public void theElectedLeaderIsExcludedEvenWhenItIsNotTheLeaderRole() {
        // No LEADER role present: electLeader picks the most powerful (the drafter here).
        AgentTeam.AgentSpec drafter = spec(AgentRole.EXPLOIT_DRAFTER, LlmProvider.OPENAI, ReasoningEffort.MAX, 9000);
        AgentTeam.AgentSpec verifier = spec(AgentRole.VERIFIER, LlmProvider.XAI, ReasoningEffort.LOW, 2000);
        AgentTeam.Plan plan = AgentTeam.plan(List.of(drafter, verifier));

        assertSame(drafter, plan.leader());
        assertEquals(List.of(verifier), AgentOrchestrator.workerOrder(plan));
    }

    // ---- systemPromptFor ----

    @Test
    public void everyRoleHasANonEmptyAuthorisationScopedPrompt() {
        for (AgentRole role : AgentRole.values()) {
            String prompt = AgentOrchestrator.systemPromptFor(role);
            assertNotNull(prompt);
            assertFalse(prompt.isBlank());
            assertTrue("prompt should scope to authorised work: " + role,
                    prompt.toUpperCase().contains("AUTHORISED"));
        }
    }

    @Test
    public void theLeaderPromptInstructsTheProposedActionMarker() {
        assertTrue(AgentOrchestrator.systemPromptFor(AgentRole.LEADER).contains(AgentOrchestrator.PROPOSED_ACTION_MARKER));
    }

    @Test
    public void drafterAndVerifierPromptsForbidExecution() {
        assertTrue(AgentOrchestrator.systemPromptFor(AgentRole.EXPLOIT_DRAFTER).toLowerCase().contains("on paper"));
        assertTrue(AgentOrchestrator.systemPromptFor(AgentRole.EXPLOIT_DRAFTER).toUpperCase().contains("DO NOT EXECUTE")
                || AgentOrchestrator.systemPromptFor(AgentRole.EXPLOIT_DRAFTER).toLowerCase().contains("do not execute"));
    }

    // ---- userPromptFor ----

    @Test
    public void reconGetsOnlyTheInventoryNotPriorAnalysis() {
        List<AgentOrchestrator.RoundResult> prior = List.of(round(AgentRole.RECON, LlmProvider.GEMINI, "should not appear"));
        String prompt = AgentOrchestrator.userPromptFor(AgentRole.RECON, "INVENTORY-XYZ", prior);
        assertTrue(prompt.contains("INVENTORY-XYZ"));
        assertFalse(prompt.contains("TEAM ANALYSIS SO FAR"));
    }

    @Test
    public void laterRolesReceiveInventoryPlusPriorRounds() {
        List<AgentOrchestrator.RoundResult> prior = List.of(
                round(AgentRole.RECON, LlmProvider.GEMINI, "recon says focus on IDOR"),
                round(AgentRole.EXPLOIT_DRAFTER, LlmProvider.OPENAI, "draft PoC steps"));
        String prompt = AgentOrchestrator.userPromptFor(AgentRole.VERIFIER, "INVENTORY-XYZ", prior);
        assertTrue(prompt.contains("INVENTORY-XYZ"));
        assertTrue(prompt.contains("TEAM ANALYSIS SO FAR"));
        assertTrue(prompt.contains("recon says focus on IDOR"));
        assertTrue(prompt.contains("draft PoC steps"));
    }

    // ---- extractProposedActions ----

    @Test
    public void extractsProposedActionLinesIncludingBulletedOnes() {
        String leader = "Summary of the assessment.\n"
                + "PROPOSED ACTION: manually verify the IDOR on /api/orders/{id}\n"
                + "- PROPOSED ACTION: run sqlmap against the id parameter\n"
                + "Some trailing prose.";
        List<String> actions = AgentOrchestrator.extractProposedActions(leader);
        assertEquals(2, actions.size());
        assertEquals("manually verify the IDOR on /api/orders/{id}", actions.get(0));
        assertEquals("run sqlmap against the id parameter", actions.get(1));
    }

    @Test
    public void extractIsCaseInsensitiveOnTheMarkerAndIgnoresEmptyActions() {
        String leader = "proposed action:   \nproposed action: check the CORS reflection";
        List<String> actions = AgentOrchestrator.extractProposedActions(leader);
        assertEquals(List.of("check the CORS reflection"), actions);
    }

    @Test
    public void noMarkerMeansNoActions() {
        assertTrue(AgentOrchestrator.extractProposedActions("just a synthesis, no next steps").isEmpty());
        assertTrue(AgentOrchestrator.extractProposedActions(null).isEmpty());
    }

    // ---- decide ----

    @Test
    public void noLeaderSynthesisHolds() {
        AgentOrchestrator.Outcome outcome = AgentOrchestrator.decide(List.of(), null);
        assertEquals(AgentOrchestrator.OrchestrationDecision.HOLD, outcome.decision());
        assertTrue(outcome.escalations().isEmpty());

        assertEquals(AgentOrchestrator.OrchestrationDecision.HOLD, AgentOrchestrator.decide(List.of(), "   ").decision());
    }

    @Test
    public void allPassiveProposedActionsProceed() {
        String leader = "Ranked assessment.\n"
                + "PROPOSED ACTION: review the response headers for the missing CSP\n"
                + "PROPOSED ACTION: draft a PoC on paper for the reflected parameter";
        AgentOrchestrator.Outcome outcome = AgentOrchestrator.decide(List.of(), leader);
        assertEquals(AgentOrchestrator.OrchestrationDecision.PROCEED, outcome.decision());
        assertTrue(outcome.escalations().isEmpty());
    }

    @Test
    public void anyTargetTouchingProposedActionEscalates() {
        String leader = "Assessment.\n"
                + "PROPOSED ACTION: summarise the auth flow\n"                       // passive
                + "PROPOSED ACTION: recreate the SQL injection to confirm the PoC";  // execute -> human
        AgentOrchestrator.Outcome outcome = AgentOrchestrator.decide(List.of(), leader);
        assertEquals(AgentOrchestrator.OrchestrationDecision.ESCALATE, outcome.decision());
        assertEquals(1, outcome.escalations().size());
        assertTrue(outcome.escalations().get(0).toLowerCase().contains("recreate the sql injection"));
    }

    @Test
    public void decidePreservesTheRoundsAndTrimmedSynthesis() {
        List<AgentOrchestrator.RoundResult> rounds = List.of(round(AgentRole.LEADER, LlmProvider.ANTHROPIC, "x"));
        AgentOrchestrator.Outcome outcome = AgentOrchestrator.decide(rounds, "  synthesis text  ");
        assertEquals(rounds, outcome.rounds());
        assertEquals("synthesis text", outcome.leaderSynthesis());
    }
}
