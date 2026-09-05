package com.victor.reconloop;

import org.junit.Test;

import static org.junit.Assert.*;

/**
 * The AI-feed table model must stay aligned with {@link AiFeed.Store}: both retain the newest
 * {@code DEFAULT_CAP} events, so the table never grows unbounded or shows entries the store evicted.
 */
public class AiFeedTableModelTest {

    private static final int DETAIL_COL = 7;

    @Test
    public void tableIsCappedAndKeepsNewestLikeTheStore() {
        ReconModel.AiFeedTableModel model = new ReconModel.AiFeedTableModel();
        AiFeed.Store store = new AiFeed.Store(); // same DEFAULT_CAP

        int total = AiFeed.Store.DEFAULT_CAP + 50;
        for (int i = 0; i < total; i++) {
            AiFeed.Event e = store.record(AiFeed.Kind.TRIAGE, LlmProvider.OPENAI, "m",
                    AiFeed.Outcome.OK, 1, 1, "t", "event-" + i);
            model.add(e);
        }

        // Table is capped to the same size as the store.
        assertEquals(AiFeed.Store.DEFAULT_CAP, model.getRowCount());
        assertEquals(AiFeed.Store.DEFAULT_CAP, store.snapshot().size());

        // Newest-first: row 0 is the last event recorded; the evicted early events are gone.
        assertEquals("t — event-" + (total - 1), model.getValueAt(0, DETAIL_COL));
        int oldestKept = total - AiFeed.Store.DEFAULT_CAP;
        assertEquals("t — event-" + oldestKept, model.getValueAt(model.getRowCount() - 1, DETAIL_COL));
    }

    @Test
    public void clearEmptiesTheTable() {
        ReconModel.AiFeedTableModel model = new ReconModel.AiFeedTableModel();
        AiFeed.Store store = new AiFeed.Store();
        model.add(store.record(AiFeed.Kind.JS_REVIEW, LlmProvider.GEMINI, "g", AiFeed.Outcome.OK, 1, 0, "t", "d"));
        assertEquals(1, model.getRowCount());
        model.clear();
        assertEquals(0, model.getRowCount());
    }
}
