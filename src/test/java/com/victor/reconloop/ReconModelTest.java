package com.victor.reconloop;

import org.junit.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;

public class ReconModelTest {

    @Test
    public void sixArgConstructorDefaultsTriageToBlank() {
        ReconModel.FindingRow row = new ReconModel.FindingRow("HIGH", "generic", "secret-rule", "response", "abc123", "https://a.example");

        assertEquals("", row.triage());
    }

    @Test
    public void newRowsAreInsertedAtTheFrontMostRecentFirst() {
        ReconModel.FindingTableModel model = new ReconModel.FindingTableModel();
        model.add(new ReconModel.FindingRow("LOW", "p", "r1", "loc", "v1", "u1"));
        model.add(new ReconModel.FindingRow("HIGH", "p", "r2", "loc", "v2", "u2"));

        assertEquals(2, model.getRowCount());
        assertEquals("r2", model.getValueAt(0, 2));
        assertEquals("r1", model.getValueAt(1, 2));
    }

    @Test
    public void aiTriageColumnShowsPlaceholderUntilTriaged() {
        ReconModel.FindingTableModel model = new ReconModel.FindingTableModel();
        model.add(new ReconModel.FindingRow("LOW", "p", "r1", "loc", "v1", "u1"));

        assertEquals(7, model.getColumnCount());
        assertEquals("AI Triage", model.getColumnName(6));
        assertEquals("(not triaged)", model.getValueAt(0, 6));
    }

    @Test
    public void untriagedSnapshotExcludesAlreadyTriagedRowsInInsertionOrder() {
        ReconModel.FindingTableModel model = new ReconModel.FindingTableModel();
        model.add(new ReconModel.FindingRow("LOW", "p", "r1", "loc", "v1", "u1"));
        model.add(new ReconModel.FindingRow("HIGH", "p", "r2", "loc", "v2", "u2"));
        model.add(new ReconModel.FindingRow("MEDIUM", "p", "r3", "loc", "v3", "u3"));

        Map<String, String> verdicts = new HashMap<>();
        verdicts.put(ReconModel.FindingTableModel.correlationKey(
                new ReconModel.FindingRow("HIGH", "p", "r2", "loc", "v2", "u2")), "LIKELY_TP");
        model.applyTriage(verdicts);

        List<ReconModel.FindingRow> untriaged = model.untriagedSnapshot();
        assertEquals(2, untriaged.size());
        assertEquals("r1", untriaged.get(0).rule());
        assertEquals("r3", untriaged.get(1).rule());
    }

    @Test
    public void applyTriageRebuildsOnlyTheMatchingRowAndPreservesOtherFields() {
        ReconModel.FindingTableModel model = new ReconModel.FindingTableModel();
        model.add(new ReconModel.FindingRow("HIGH", "aws", "aws-secret-access-key", "response", "AKIA-fake", "https://a.example/x"));

        Map<String, String> verdicts = new HashMap<>();
        verdicts.put("aws-secret-access-key\0AKIA-fake\0https://a.example/x", "LIKELY_FP (tp:0 fp:2 unc:0)");
        model.applyTriage(verdicts);

        assertEquals(0, model.untriagedSnapshot().size());
        assertEquals("LIKELY_FP (tp:0 fp:2 unc:0)", model.getValueAt(0, 6));
        // Untouched fields survive the rebuild.
        assertEquals("HIGH", model.getValueAt(0, 0));
        assertEquals("aws", model.getValueAt(0, 1));
        assertEquals("response", model.getValueAt(0, 3));
    }

    @Test
    public void applyTriageIgnoresKeysThatDoNotMatchAnyRow() {
        ReconModel.FindingTableModel model = new ReconModel.FindingTableModel();
        model.add(new ReconModel.FindingRow("HIGH", "p", "r1", "loc", "v1", "u1"));

        Map<String, String> verdicts = new HashMap<>();
        verdicts.put("no-such-rule\0v1\0u1", "LIKELY_TP");
        model.applyTriage(verdicts);

        assertEquals("(not triaged)", model.getValueAt(0, 6));
    }

    @Test
    public void clearRemovesAllRows() {
        ReconModel.FindingTableModel model = new ReconModel.FindingTableModel();
        model.add(new ReconModel.FindingRow("LOW", "p", "r1", "loc", "v1", "u1"));
        model.clear();

        assertEquals(0, model.getRowCount());
        assertTrue(model.untriagedSnapshot().isEmpty());
    }
}
