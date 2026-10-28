package com.victor.reconloop;

import org.junit.Test;

import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class RelationshipChartTest {

    @Test
    public void sharesOneScriptFileAcrossHostsAndKeepsTheSubnet() {
        RelationshipChart chart = RelationshipChart.build(List.of(
                new ReconModel.AssetRow("ipv4", "10.0.0.5", "scope"),
                new ReconModel.AssetRow("ipv4", "10.0.0.6", "scope"),
                new ReconModel.AssetRow("service", "10.0.0.5:22/tcp", "naabu")
        ), List.of(
                new ReconModel.DiscoveryRow("file:.js", "https://10.0.0.5/static/app.chunk.js", "katana"),
                new ReconModel.DiscoveryRow("file:.js", "https://10.0.0.6/static/app.chunk.js", "katana"),
                new ReconModel.DiscoveryRow("endpoint", "https://10.0.0.5/", "proxy")
        ));

        List<RelationshipChart.Node> files = chart.nodes().stream().filter(node -> node.kind().equals("file")).toList();
        assertEquals(1, files.size());
        assertEquals("app.chunk.js", files.get(0).label());
        assertEquals("Served by 2 hosts.", files.get(0).detail());
        assertEquals(2, chart.edges().stream().filter(edge -> edge.verb().equals("serves") && edge.target().equals(files.get(0).id())).count());
        assertTrue(chart.nodes().stream().anyMatch(node -> node.kind().equals("net") && node.label().equals("10.0.0.0/24")));
        assertTrue(chart.edges().stream().anyMatch(edge -> edge.verb().equals("exposes") && edge.target().equals("port:10.0.0.5:tcp:22")));
        assertEquals(1, chart.nodes().stream().filter(node -> node.kind().equals("file")).count());

        String json = chart.meridianJson();
        assertTrue(json.contains("\"meridian\":1"));
        assertEquals(2, json.split("app.chunk.js", -1).length - 1);
        assertFalse(json.contains("\"kind\":\"endpoint\""));
    }

    @Test
    public void emptyScopeStaysEmpty() {
        RelationshipChart chart = RelationshipChart.build(List.of(), List.of());
        assertTrue(chart.empty());
        assertTrue(chart.meridianJson().contains("\"hosts\":[]"));
    }

    @Test
    public void fileKindRecognisesScriptSuffixesOnly() {
        assertEquals("chunk", RelationshipChart.fileKind("/static/app.chunk.js"));
        assertEquals("map", RelationshipChart.fileKind("/app.js.map"));
        assertEquals("ts", RelationshipChart.fileKind("/src/main.ts"));
        assertEquals("", RelationshipChart.fileKind("/index.html"));
    }
}
