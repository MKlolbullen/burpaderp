package com.victor.reconloop;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

public final class ReconLoopExtension implements BurpExtension {
    private ReconController controller;

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Recon Hound");

        ReconModel.FindingTableModel findingModel = new ReconModel.FindingTableModel();
        ReconModel.DiscoveryTableModel discoveryModel = new ReconModel.DiscoveryTableModel();
        ReconModel.ParameterTableModel parameterModel = new ReconModel.ParameterTableModel();
        ReconModel.ReflectionTableModel reflectionModel = new ReconModel.ReflectionTableModel();
        ReconModel.ActiveTableModel activeModel = new ReconModel.ActiveTableModel();
        ReconModel.AssetTableModel assetModel = new ReconModel.AssetTableModel();
        controller = new ReconController(api, findingModel, discoveryModel, parameterModel, reflectionModel, activeModel, assetModel);

        ReconPanel panel = new ReconPanel(api, controller, findingModel, discoveryModel, parameterModel, reflectionModel, activeModel, assetModel);

        api.http().registerHttpHandler(controller);
        api.userInterface().registerSuiteTab("Recon Hound", panel);
        api.userInterface().registerContextMenuItemsProvider(new ReconContextMenu(panel));
        api.extension().registerUnloadingHandler(() -> controller.shutdown());

        api.logging().logToOutput("Recon Hound loaded.");
        api.logging().logToOutput("Features: asset/file discovery, redirect-chain scanning, parameter profiling, RegexHound, gf-json packs, payload corpus indexing.");
        api.logging().logToOutput("Passive XSS surface mapping: reflection-context detection with cheat-sheet vector suggestions (no auto-firing).");
        api.logging().logToOutput("Optional active tests (opt-in, off by default): crt.sh subdomain enum, Arjun-style parameter discovery, and Collaborator-backed SSRF/SSTI/XSS probing.");
        api.logging().logToOutput("Every finding (passive, active, OOB, LLM) is filed as a native Burp audit issue on the site map (Dashboard / Issues), not just the plugin tabs.");
        api.logging().logToOutput("AI: right-click any request/response for manual LLM review, or use 'Analyze in-scope JS' for an on-demand, budget-capped JS bug-hunt that files findings (bug + PoC + chain) as Burp issues.");
        api.logging().logToOutput("Active GET discovery is scope-bounded, same-origin by default, capped, and deduplicated.");
    }
}
