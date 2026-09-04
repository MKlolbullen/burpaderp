package com.victor.reconloop;

import org.junit.Test;

import static org.junit.Assert.*;

/**
 * Tests for the {@link ActionGate} human-in-the-loop safety gate.
 */
public class ActionGateTest {

    // ---- decisionFor ----

    /** Verifies that passive analysis and draft PoC actions are auto-approved. */
    @Test
    public void onlyReadingAndDraftingAreAutoApproved() {
        assertEquals(ActionGate.GateDecision.AUTO_APPROVED, ActionGate.decisionFor(ActionGate.ActionKind.PASSIVE_ANALYSIS));
        assertEquals(ActionGate.GateDecision.AUTO_APPROVED, ActionGate.decisionFor(ActionGate.ActionKind.DRAFT_POC));
    }

    /** Verifies that active probes, PoC execution, and destructive actions require human approval. */
    @Test
    public void everythingThatTouchesTheTargetRequiresAHuman() {
        assertTrue(ActionGate.requiresHuman(ActionGate.ActionKind.ACTIVE_PROBE));
        assertTrue(ActionGate.requiresHuman(ActionGate.ActionKind.EXECUTE_POC));
        assertTrue(ActionGate.requiresHuman(ActionGate.ActionKind.DESTRUCTIVE));
    }

    /** Verifies that unknown actions fail closed and require human approval. */
    @Test
    public void unknownFailsClosedToRequiresHuman() {
        assertTrue(ActionGate.requiresHuman(ActionGate.ActionKind.UNKNOWN));
    }

    // ---- classify ----

    /** Verifies classification of passive analysis actions like review and analyze. */
    @Test
    public void classifiesPassiveAnalysis() {
        assertEquals(ActionGate.ActionKind.PASSIVE_ANALYSIS, ActionGate.classify("Analyze the JavaScript for DOM XSS sinks"));
        assertEquals(ActionGate.ActionKind.PASSIVE_ANALYSIS, ActionGate.classify("Review the response and identify the auth logic"));
    }

    /** Verifies that drafting PoCs is classified as DRAFT_POC, not EXECUTE_POC. */
    @Test
    public void classifiesDraftingAPocAsDraftNotExecute() {
        assertEquals(ActionGate.ActionKind.DRAFT_POC, ActionGate.classify("Draft a proof-of-concept for the reflected parameter"));
        assertEquals(ActionGate.ActionKind.DRAFT_POC, ActionGate.classify("Describe how an attacker would exploit this, on paper"));
    }

    /** Verifies classification of active probing actions like send request and fuzz. */
    @Test
    public void classifiesActiveProbe() {
        assertEquals(ActionGate.ActionKind.ACTIVE_PROBE, ActionGate.classify("Send a request with the payload to the endpoint"));
        assertEquals(ActionGate.ActionKind.ACTIVE_PROBE, ActionGate.classify("Fuzz the id parameter with sqlmap"));
    }

    /** Verifies classification of vulnerability execution and recreation as EXECUTE_POC. */
    @Test
    public void classifiesExecutingOrRecreatingAVulnAsExecutePoc() {
        assertEquals(ActionGate.ActionKind.EXECUTE_POC, ActionGate.classify("Recreate the vulnerability to confirm the PoC"));
        assertEquals(ActionGate.ActionKind.EXECUTE_POC, ActionGate.classify("Run the exploit against the staging host"));
    }

    /** Verifies classification of destructive actions like delete and drop table. */
    @Test
    public void classifiesDestructiveActions() {
        assertEquals(ActionGate.ActionKind.DESTRUCTIVE, ActionGate.classify("Delete the user records after confirming access"));
        assertEquals(ActionGate.ActionKind.DESTRUCTIVE, ActionGate.classify("drop table sessions"));
    }

    /** Verifies that when actions mix risk levels, the higher-risk interpretation wins. */
    @Test
    public void higherRiskSignalWinsWhenActionMixesVerbs() {
        // "analyze ... then execute" contains both, but the risky interpretation must win.
        assertEquals(ActionGate.ActionKind.EXECUTE_POC,
                ActionGate.classify("Analyze the flow and then execute the exploit to verify"));
        // A plan that drafts then sends is active, so the active interpretation wins over "draft".
        assertEquals(ActionGate.ActionKind.ACTIVE_PROBE,
                ActionGate.classify("Draft the payload then send the request to the server"));
    }

    /** Verifies that blank or unrecognized actions are classified as UNKNOWN. */
    @Test
    public void blankOrUnrecognisedActionsAreUnknown() {
        assertEquals(ActionGate.ActionKind.UNKNOWN, ActionGate.classify(null));
        assertEquals(ActionGate.ActionKind.UNKNOWN, ActionGate.classify("   "));
        assertEquals(ActionGate.ActionKind.UNKNOWN, ActionGate.classify("ponder the meaning of the endpoint"));
    }

    // ---- gate (classify + decide) ----

    /** Verifies the combined classify-and-decide gate method for typical scenarios. */
    @Test
    public void gateAutoApprovesReadingButHoldsRecreatingAVuln() {
        assertEquals(ActionGate.GateDecision.AUTO_APPROVED, ActionGate.gate("Summarize the request's attack surface"));
        assertEquals(ActionGate.GateDecision.REQUIRES_HUMAN, ActionGate.gate("Recreate the vulnerability to build a PoC"));
    }
}
