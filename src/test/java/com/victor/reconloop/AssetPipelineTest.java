package com.victor.reconloop;

import com.victor.reconloop.contracts.PayloadFamily;
import org.junit.Test;

import java.util.Set;

import static org.junit.Assert.*;

public class AssetPipelineTest {

    @Test
    public void quarantinesInvalidHostsAndKeepsValidInScopeOnes() {
        ReconModel.QuarantineTableModel model = new ReconModel.QuarantineTableModel();
        AssetPipeline pipeline = new AssetPipeline(model, false);

        assertFalse(pipeline.acceptHost("not a host", true, "amass"));
        assertFalse(pipeline.acceptHost("user@example.com", true, "amass"));
        assertTrue(pipeline.acceptHost("api.example.com", true, "subfinder"));
        assertFalse(pipeline.acceptHost("evil.com", false, "subfinder"));
        assertEquals(3, model.getRowCount());
    }

    @Test
    public void mapsProfilerClassesOntoPayloadFamily() {
        AssetPipeline pipeline = new AssetPipeline(new ReconModel.QuarantineTableModel(), false);
        assertEquals(PayloadFamily.XSS, pipeline.familyFor(Set.of("XSS", "numeric mutation")));
        assertEquals(PayloadFamily.LFI, pipeline.familyFor(Set.of("LFI/path traversal")));
        assertEquals(PayloadFamily.GENERIC, pipeline.familyFor(Set.of()));
    }

    @Test
    public void newRunClearsQuarantine() {
        ReconModel.QuarantineTableModel model = new ReconModel.QuarantineTableModel();
        AssetPipeline pipeline = new AssetPipeline(model, false);
        pipeline.acceptHost("nope", true, "x");
        assertEquals(1, model.getRowCount());
        var first = pipeline.runId();
        pipeline.newRun();
        assertEquals(0, model.getRowCount());
        assertNotEquals(first, pipeline.runId());
    }
}
