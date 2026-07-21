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
        controller = new ReconController(api, findingModel, discoveryModel, parameterModel, reflectionModel);

        api.http().registerHttpHandler(controller);
        api.userInterface().registerSuiteTab(
                "Recon Hound",
                new ReconPanel(api, controller, findingModel, discoveryModel, parameterModel, reflectionModel)
        );
        api.extension().registerUnloadingHandler(() -> controller.shutdown());

        api.logging().logToOutput("Recon Hound loaded.");
        api.logging().logToOutput("Features: asset/file discovery, redirect-chain scanning, parameter profiling, RegexHound, gf-json packs, payload corpus indexing.");
        api.logging().logToOutput("Passive XSS surface mapping: reflection-context detection with cheat-sheet vector suggestions (no auto-firing).");
        api.logging().logToOutput("Active GET discovery is scope-bounded, same-origin by default, capped, and deduplicated.");
    }
}
