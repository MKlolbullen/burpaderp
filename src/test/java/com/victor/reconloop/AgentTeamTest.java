package com.victor.reconloop;

import org.junit.Test;

import java.util.List;
import java.util.Optional;

import static org.junit.Assert.*;

public class AgentTeamTest {

    private static AgentTeam.AgentSpec spec(AgentRole role, LlmProvider provider, ReasoningEffort effort, int budget) {
        return new AgentTeam.AgentSpec(role, provider, null, "key", effort, budget);
    }

    // ---- AgentRole defaults ----

    @Test
    public void eachProviderMapsToItsDefaultRole() {
        assertEquals(AgentRole.LEADER, AgentRole.defaultRoleFor(LlmProvider.ANTHROPIC));
        assertEquals(AgentRole.RECON, AgentRole.defaultRoleFor(LlmProvider.GEMINI));
        assertEquals(AgentRole.EXPLOIT_DRAFTER, AgentRole.defaultRoleFor(LlmProvider.OPENAI));
        assertEquals(AgentRole.VERIFIER, AgentRole.defaultRoleFor(LlmProvider.XAI));
        assertEquals(AgentRole.UNCENSORED, AgentRole.defaultRoleFor(LlmProvider.VENICE));
    }

    @Test
    public void onlyExploitDrafterAndUncensoredAreSensitive() {
        assertTrue(AgentRole.EXPLOIT_DRAFTER.sensitive());
        assertTrue(AgentRole.UNCENSORED.sensitive());
        assertFalse(AgentRole.LEADER.sensitive());
        assertFalse(AgentRole.RECON.sensitive());
        assertFalse(AgentRole.VERIFIER.sensitive());
    }

    // ---- electLeader ----

    @Test
    public void emptyOrNullRosterElectsNoLeader() {
        assertEquals(Optional.empty(), AgentTeam.electLeader(List.of()));
        assertEquals(Optional.empty(), AgentTeam.electLeader(null));
    }

    @Test
    public void anExplicitLeaderRoleWinsEvenWithLowerPower() {
        AgentTeam.AgentSpec explicitLeader = spec(AgentRole.LEADER, LlmProvider.ANTHROPIC, ReasoningEffort.LOW, 1000);
        AgentTeam.AgentSpec strongerButNotLeader = spec(AgentRole.RECON, LlmProvider.OPENAI, ReasoningEffort.MAX, 100000);

        assertEquals(Optional.of(explicitLeader),
                AgentTeam.electLeader(List.of(strongerButNotLeader, explicitLeader)));
    }

    @Test
    public void withoutAnExplicitLeaderTheMostPowerfulMemberLeads() {
        AgentTeam.AgentSpec weak = spec(AgentRole.RECON, LlmProvider.GEMINI, ReasoningEffort.LOW, 2000);
        AgentTeam.AgentSpec strong = spec(AgentRole.VERIFIER, LlmProvider.OPENAI, ReasoningEffort.MAX, 1000);

        assertEquals(Optional.of(strong), AgentTeam.electLeader(List.of(weak, strong)));
    }

    @Test
    public void effortDominatesBudgetInPowerScore() {
        AgentTeam.AgentSpec highEffortSmallBudget = spec(AgentRole.RECON, LlmProvider.OPENAI, ReasoningEffort.HIGH, 1);
        AgentTeam.AgentSpec lowEffortHugeBudget = spec(AgentRole.VERIFIER, LlmProvider.XAI, ReasoningEffort.LOW, 999999);

        assertEquals(Optional.of(highEffortSmallBudget),
                AgentTeam.electLeader(List.of(lowEffortHugeBudget, highEffortSmallBudget)));
    }

    @Test
    public void tiesAreBrokenByConfigurationOrder() {
        AgentTeam.AgentSpec first = spec(AgentRole.RECON, LlmProvider.OPENAI, ReasoningEffort.HIGH, 5000);
        AgentTeam.AgentSpec second = spec(AgentRole.VERIFIER, LlmProvider.XAI, ReasoningEffort.HIGH, 5000);

        assertEquals(Optional.of(first), AgentTeam.electLeader(List.of(first, second)));
    }

    // ---- plan / describe / hasSensitiveMember ----

    @Test
    public void planPreservesMemberOrderAndElectsLeader() {
        AgentTeam.AgentSpec leader = spec(AgentRole.LEADER, LlmProvider.ANTHROPIC, ReasoningEffort.MAX, 8000);
        AgentTeam.AgentSpec recon = spec(AgentRole.RECON, LlmProvider.GEMINI, ReasoningEffort.LOW, 2000);
        AgentTeam.Plan plan = AgentTeam.plan(List.of(recon, leader));

        assertEquals(List.of(recon, leader), plan.members());
        assertSame(leader, plan.leader());
    }

    @Test
    public void describeStarsTheLeaderAndNamesEveryMember() {
        AgentTeam.AgentSpec leader = spec(AgentRole.LEADER, LlmProvider.ANTHROPIC, ReasoningEffort.MAX, 8000);
        AgentTeam.AgentSpec recon = spec(AgentRole.RECON, LlmProvider.GEMINI, ReasoningEffort.LOW, 2000);
        String description = AgentTeam.describe(AgentTeam.plan(List.of(leader, recon)));

        assertTrue(description.contains("★ " + AgentRole.LEADER.title()));
        assertTrue(description.contains(AgentRole.RECON.title()));
        assertTrue(description.contains("escalates to a human"));
    }

    @Test
    public void describeUsesTheProviderDefaultModelWhenNoneIsConfigured() {
        AgentTeam.AgentSpec recon = new AgentTeam.AgentSpec(
                AgentRole.RECON, LlmProvider.GEMINI, "", "key", ReasoningEffort.MEDIUM, 4000);
        assertTrue(AgentTeam.describe(AgentTeam.plan(List.of(recon)))
                .contains(LlmProvider.GEMINI.defaultModel()));
    }

    @Test
    public void emptyPlanDescribesAsNoAgents() {
        assertEquals("No agents enabled.", AgentTeam.describe(AgentTeam.plan(List.of())));
        assertEquals("No agents enabled.", AgentTeam.describe(null));
    }

    @Test
    public void hasSensitiveMemberReflectsRoles() {
        AgentTeam.AgentSpec recon = spec(AgentRole.RECON, LlmProvider.GEMINI, ReasoningEffort.LOW, 2000);
        AgentTeam.AgentSpec drafter = spec(AgentRole.EXPLOIT_DRAFTER, LlmProvider.OPENAI, ReasoningEffort.HIGH, 6000);

        assertFalse(AgentTeam.hasSensitiveMember(AgentTeam.plan(List.of(recon))));
        assertTrue(AgentTeam.hasSensitiveMember(AgentTeam.plan(List.of(recon, drafter))));
    }
}
