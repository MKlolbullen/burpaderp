package com.victor.reconloop;

import burp.api.montoya.MontoyaApi;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.TreeSet;

final class ReconPanel extends JPanel {
    /** One configurable row per {@link LlmProvider} — enabling several at once lets JS bug-hunting and
     *  triage fan out across providers concurrently instead of being limited to a single active one. */
    private record CredentialRow(LlmProvider provider, JCheckBox enabled, JTextField model, JPasswordField key) {}

    private JTabbedPane tabs;
    private Component aiTab;
    private List<CredentialRow> credentialRows;
    private JTextArea aiSystem;
    private JTextArea aiInput;
    private JTextArea aiOutput;
    private JButton aiAnalyze;

    ReconPanel(MontoyaApi api, ReconController controller,
               ReconModel.FindingTableModel findingModel,
               ReconModel.DiscoveryTableModel discoveryModel,
               ReconModel.ParameterTableModel parameterModel,
               ReconModel.ReflectionTableModel reflectionModel,
               ReconModel.ActiveTableModel activeModel,
               ReconModel.AssetTableModel assetModel) {
        super(new BorderLayout(8, 8));

        JTextArea seeds = new JTextArea(5, 80);
        seeds.setLineWrap(false);
        seeds.setToolTipText("One http(s) seed URL per line");

        JCheckBox autoLoop = new JCheckBox("Auto-loop discovered resources", true);
        JCheckBox addScope = new JCheckBox("Add discovered files/directories to Burp scope", true);
        JCheckBox sameOrigin = new JCheckBox("Same-origin discovery only", true);
        JCheckBox includeInfo = new JCheckBox("Include informational RegexHound matches", false);
        JCheckBox gfPatterns = new JCheckBox("Scan ~/.gf/*.json patterns", true);
        JCheckBox redirects = new JCheckBox("Follow and scan redirects", true);
        JCheckBox reflections = new JCheckBox("Detect reflected parameters (passive XSS surface)", true);
        JSpinner maxRequests = new JSpinner(new SpinnerNumberModel(500, 1, 100000, 50));
        JSpinner maxRedirects = new JSpinner(new SpinnerNumberModel(8, 0, 50, 1));

        JButton addSeeds = new JButton("Add seeds + start");
        JButton queueSiteMap = new JButton("Queue current in-scope site map");
        JButton pause = new JButton("Pause");
        JButton resume = new JButton("Resume");
        JButton reset = new JButton("Reset state");

        JPanel controls = new JPanel();
        controls.setLayout(new BoxLayout(controls, BoxLayout.Y_AXIS));
        controls.add(new JLabel("Seed hosts / URLs (one per line):"));
        controls.add(new JScrollPane(seeds));

        JPanel optionsA = new JPanel(new FlowLayout(FlowLayout.LEFT));
        optionsA.add(autoLoop); optionsA.add(addScope); optionsA.add(sameOrigin);
        optionsA.add(redirects); optionsA.add(gfPatterns); optionsA.add(includeInfo);
        optionsA.add(reflections);
        controls.add(optionsA);

        JPanel optionsB = new JPanel(new FlowLayout(FlowLayout.LEFT));
        optionsB.add(new JLabel("Max active requests:")); optionsB.add(maxRequests);
        optionsB.add(new JLabel("Max redirect hops:")); optionsB.add(maxRedirects);
        optionsB.add(new JLabel("GF packs: " + controller.gfPackCount()));
        optionsB.add(new JLabel("Payload corpus: " + controller.payloadCount() + " lines"));
        controls.add(optionsB);

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT));
        buttons.add(addSeeds); buttons.add(queueSiteMap); buttons.add(pause); buttons.add(resume); buttons.add(reset);
        controls.add(buttons);

        JLabel payloads = new JLabel("Payload categories: " + controller.payloadCategories());
        controls.add(payloads);

        // ---- Active testing (opt-in) ----
        JCheckBox activeEnabled = new JCheckBox("Enable active tests (fires payloads — authorized targets only)", false);
        JSpinner activeBudget = new JSpinner(new SpinnerNumberModel(60, 1, 5000, 10));
        JTextField ctDomain = new JTextField(18);
        JButton ctButton = new JButton("Enumerate (crt.sh)");
        JTextField paramUrl = new JTextField(22);
        JButton paramButton = new JButton("Discover params (Arjun)");
        JTextField graphqlUrl = new JTextField(22);
        JButton graphqlButton = new JButton("Introspect GraphQL");
        JButton graphqlFuzzButton = new JButton("Fuzz GraphQL");
        JButton runActive = new JButton("Run active tests on in-scope site map");
        JButton runJwt = new JButton("Run JWT alg:none test");
        JButton runTakeover = new JButton("Subdomain takeover check");

        JPanel activePanel = new JPanel();
        activePanel.setLayout(new BoxLayout(activePanel, BoxLayout.Y_AXIS));
        activePanel.setBorder(BorderFactory.createTitledBorder("Active testing (opt-in) — SSRF / SSTI / XSS via Burp Collaborator"));

        JPanel activeRow1 = new JPanel(new FlowLayout(FlowLayout.LEFT));
        activeRow1.add(activeEnabled);
        activeRow1.add(new JLabel("Per-request budget:")); activeRow1.add(activeBudget);
        activeRow1.add(runActive);
        activePanel.add(activeRow1);

        JPanel activeRow2 = new JPanel(new FlowLayout(FlowLayout.LEFT));
        activeRow2.add(new JLabel("crt.sh domain:")); activeRow2.add(ctDomain); activeRow2.add(ctButton);
        activeRow2.add(new JLabel("Param-discovery URL:")); activeRow2.add(paramUrl); activeRow2.add(paramButton);
        activeRow2.add(new JLabel("Param wordlist: " + controller.paramWordlistSize()));
        activePanel.add(activeRow2);

        JPanel activeRow3 = new JPanel(new FlowLayout(FlowLayout.LEFT));
        activeRow3.add(new JLabel("GraphQL URL:")); activeRow3.add(graphqlUrl); activeRow3.add(graphqlButton);
        activeRow3.add(graphqlFuzzButton);
        activePanel.add(activeRow3);

        JPanel activeRow4 = new JPanel(new FlowLayout(FlowLayout.LEFT));
        activeRow4.add(runJwt);
        activeRow4.add(runTakeover);
        activeRow4.add(new JLabel("(opt-in — JWT replays GET/HEAD/OPTIONS; takeover fetches enumerated hosts)"));
        activePanel.add(activeRow4);

        // Access-control / IDOR (Autorize-style)
        JTextArea acHeaders = new JTextArea(2, 60);
        acHeaders.setToolTipText("Alternate identity headers, one per line, e.g. 'Cookie: session=lowpriv' or 'Authorization: Bearer ...'");
        JCheckBox acUnauth = new JCheckBox("Unauthenticated (strip auth)", false);
        JButton acButton = new JButton("Run access-control test (safe methods)");
        JPanel acRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        acRow.add(new JLabel("Access-control alternate identity:"));
        acRow.add(new JScrollPane(acHeaders));
        acRow.add(acUnauth);
        acRow.add(acButton);
        activePanel.add(acRow);
        controls.add(activePanel);

        JLabel status = new JLabel(controller.status());
        controls.add(status);
        add(controls, BorderLayout.NORTH);

        JTable findings = new JTable(findingModel);
        findings.setAutoCreateRowSorter(true);
        JTable discoveries = new JTable(discoveryModel);
        discoveries.setAutoCreateRowSorter(true);
        JTable parameters = new JTable(parameterModel);
        parameters.setAutoCreateRowSorter(true);
        JTable reflectionTable = new JTable(reflectionModel);
        reflectionTable.setAutoCreateRowSorter(true);
        JTable activeTable = new JTable(activeModel);
        activeTable.setAutoCreateRowSorter(true);
        JTable assetTable = new JTable(assetModel);
        assetTable.setAutoCreateRowSorter(true);
        JTable vectorTable = buildVectorReferenceTable();

        tabs = new JTabbedPane();
        tabs.addTab("Findings", buildFindingsPanel(controller, findings));
        tabs.addTab("Discovered resources", new JScrollPane(discoveries));
        tabs.addTab("Insertion points", new JScrollPane(parameters));
        tabs.addTab("XSS reflections", new JScrollPane(reflectionTable));
        tabs.addTab("Active tests", new JScrollPane(activeTable));
        tabs.addTab("Hosts / IPs", buildAssetPanel(controller, assetTable, assetModel));
        tabs.addTab("XSS vector library", new JScrollPane(vectorTable));
        aiTab = buildAiPanel(controller);
        tabs.addTab("AI analysis", aiTab);
        tabs.addTab("Nuclei templates (AI)", buildNucleiPanel(controller));
        add(tabs, BorderLayout.CENTER);

        autoLoop.addActionListener(e -> controller.setCrawlEnabled(autoLoop.isSelected()));
        addScope.addActionListener(e -> controller.setAddToScope(addScope.isSelected()));
        sameOrigin.addActionListener(e -> controller.setSameOriginOnly(sameOrigin.isSelected()));
        includeInfo.addActionListener(e -> controller.setIncludeInfoFindings(includeInfo.isSelected()));
        gfPatterns.addActionListener(e -> controller.setScanGfPatterns(gfPatterns.isSelected()));
        redirects.addActionListener(e -> controller.setFollowRedirects(redirects.isSelected()));
        reflections.addActionListener(e -> controller.setDetectReflections(reflections.isSelected()));
        activeEnabled.addActionListener(e -> controller.setActiveTestsEnabled(activeEnabled.isSelected()));
        activeBudget.addChangeListener(e -> controller.setActiveRequestBudget((Integer) activeBudget.getValue()));
        ctButton.addActionListener(e -> controller.enumerateSubdomains(ctDomain.getText()));
        paramButton.addActionListener(e -> controller.discoverParameters(paramUrl.getText()));
        graphqlButton.addActionListener(e -> controller.introspectGraphql(graphqlUrl.getText()));
        graphqlFuzzButton.addActionListener(e -> controller.fuzzGraphql(graphqlUrl.getText()));
        runActive.addActionListener(e -> controller.runActiveTests());
        runJwt.addActionListener(e -> controller.runJwtAttacks());
        runTakeover.addActionListener(e -> controller.runSubdomainTakeoverCheck());
        acButton.addActionListener(e -> controller.runAccessControlTest(acHeaders.getText(), acUnauth.isSelected()));
        maxRequests.addChangeListener(e -> controller.setMaxRequests((Integer) maxRequests.getValue()));
        maxRedirects.addChangeListener(e -> controller.setMaxRedirects((Integer) maxRedirects.getValue()));
        addSeeds.addActionListener(e -> {
            controller.setCrawlEnabled(true);
            autoLoop.setSelected(true);
            controller.enqueueSeeds(seeds.getText());
        });
        queueSiteMap.addActionListener(e -> controller.queueCurrentInScopeSiteMap());
        pause.addActionListener(e -> { controller.pause(); autoLoop.setSelected(false); });
        resume.addActionListener(e -> { controller.resume(); autoLoop.setSelected(true); });
        reset.addActionListener(e -> controller.reset());

        controller.setStatusListener(status::setText);
        api.userInterface().applyThemeToComponent(this);
    }

    /** Loads content into the AI tab, optionally sets a system-prompt preset, selects the tab, and runs. */
    void sendToAi(String text, String systemPreset) {
        if (aiInput == null) return;
        SwingUtilities.invokeLater(() -> {
            if (systemPreset != null && !systemPreset.isBlank()) aiSystem.setText(systemPreset);
            aiInput.setText(text == null ? "" : text);
            aiInput.setCaretPosition(0);
            if (aiTab != null) tabs.setSelectedComponent(aiTab);
            aiAnalyze.doClick();
        });
    }

    /**
     * Resolves every enabled provider row into a ready-to-use credential (UI key, or its $ENV
     * fallback). Rows that are checked but resolve to no key at all are silently skipped — a caller
     * with an empty result treats that the same as "no provider selected".
     */
    private List<LlmClient.LlmCredential> enabledCredentials() {
        List<LlmClient.LlmCredential> out = new ArrayList<>();
        if (credentialRows == null) return out;
        for (CredentialRow row : credentialRows) {
            if (!row.enabled().isSelected()) continue;
            String uiKey = new String(row.key().getPassword()).trim();
            String resolvedKey = !uiKey.isBlank() ? uiKey : System.getenv(row.provider().envVar());
            if (resolvedKey == null || resolvedKey.isBlank()) continue;
            String model = row.model().getText();
            out.add(new LlmClient.LlmCredential(row.provider(),
                    model == null || model.isBlank() ? row.provider().defaultModel() : model.trim(),
                    resolvedKey));
        }
        return out;
    }

    private JPanel buildAiPanel(ReconController controller) {
        JPanel panel = new JPanel(new BorderLayout(6, 6));

        JButton analyze = new JButton("Analyze");
        JButton clearKeys = new JButton("Clear all keys");
        JSpinner jsBudget = new JSpinner(new SpinnerNumberModel(15, 1, 500, 5));
        JButton analyzeJs = new JButton("Analyze in-scope JS → Burp issues");
        analyzeJs.setToolTipText("Sends in-scope JavaScript from the site map to the enabled LLM provider(s), "
                + "up to the file budget, and files each structured finding (bug + PoC + chain) as a native Burp issue. "
                + "With more than one provider enabled, files are round-robined across them concurrently.");
        JButton analyzeChains = new JButton("Chain findings → exploit chains");
        analyzeChains.setToolTipText("Sends the in-scope finding inventory (all audit issues) to the first enabled LLM provider "
                + "and files ranked exploit chains (writeup + reproducible steps) as native Burp issues.");
        this.aiAnalyze = analyze;

        List<CredentialRow> rows = new ArrayList<>();
        JPanel providersPanel = new JPanel(new GridLayout(0, 1, 2, 2));
        providersPanel.setBorder(BorderFactory.createTitledBorder(
                "LLM providers — enable one or more; multiple run together (JS bug-hunt throughput, triage ensemble voting)"));
        for (LlmProvider p : LlmProvider.values()) {
            JCheckBox enabled = new JCheckBox(p.label());
            JTextField model = new JTextField(p.defaultModel(), 16);
            JPasswordField key = new JPasswordField(18);
            key.setToolTipText("Leave blank to use $" + p.envVar() + "; kept in memory only, never saved.");
            JPanel row = new JPanel(new FlowLayout(FlowLayout.LEFT));
            row.add(enabled);
            row.add(new JLabel("Model:")); row.add(model);
            row.add(new JLabel("Key:")); row.add(key);
            providersPanel.add(row);
            rows.add(new CredentialRow(p, enabled, model, key));
        }
        this.credentialRows = rows;

        JPanel top = new JPanel(new BorderLayout(4, 4));
        top.add(providersPanel, BorderLayout.CENTER);
        JPanel topButtons = new JPanel(new FlowLayout(FlowLayout.LEFT));
        topButtons.add(analyze);
        topButtons.add(clearKeys);
        top.add(topButtons, BorderLayout.SOUTH);

        JPanel jsBar = new JPanel(new FlowLayout(FlowLayout.LEFT));
        jsBar.add(new JLabel("Automated JS bug-hunt — files/run:"));
        jsBar.add(jsBudget);
        jsBar.add(analyzeJs);
        jsBar.add(analyzeChains);
        jsBar.add(new JLabel("(on-demand; results become native Burp issues)"));

        JTextArea system = new JTextArea(LlmClient.DEFAULT_JS_SYSTEM_PROMPT, 3, 80);
        system.setLineWrap(true); system.setWrapStyleWord(true);
        JTextArea input = new JTextArea(12, 80);
        input.setToolTipText("Paste JavaScript, recovered source, a response, or a finding to analyze.");
        JTextArea output = new JTextArea(14, 80);
        output.setEditable(false); output.setLineWrap(true); output.setWrapStyleWord(true);
        this.aiSystem = system;
        this.aiInput = input;
        this.aiOutput = output;

        JPanel prompts = new JPanel(new GridLayout(0, 1, 4, 4));
        prompts.add(new JLabel("System prompt:"));
        prompts.add(new JScrollPane(system));
        prompts.add(new JLabel("Input (sent to the selected third-party LLM — authorized data only):"));
        prompts.add(new JScrollPane(input));

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, prompts, new JScrollPane(output));
        split.setResizeWeight(0.6);

        JLabel privacy = new JLabel("Nothing is sent until you click a button. Data leaves Burp to the selected third-party LLM — authorized data only.");

        JPanel north = new JPanel();
        north.setLayout(new BoxLayout(north, BoxLayout.Y_AXIS));
        north.add(top);
        north.add(jsBar);
        panel.add(north, BorderLayout.NORTH);
        panel.add(split, BorderLayout.CENTER);
        panel.add(privacy, BorderLayout.SOUTH);

        clearKeys.addActionListener(e -> { for (CredentialRow row : rows) row.key().setText(""); });
        analyzeJs.addActionListener(e -> {
            List<LlmClient.LlmCredential> creds = enabledCredentials();
            if (creds.isEmpty()) { output.setText("[enable an LLM provider and set its key above]"); return; }
            int budget = (Integer) jsBudget.getValue();
            output.setText("Analyzing up to " + budget + " in-scope JS file(s) across " + creds.size()
                    + " provider(s)... findings will appear as native Burp issues and in the Findings/Active tabs.");
            analyzeJs.setEnabled(false);
            analyze.setEnabled(false);
            controller.analyzeInScopeJavaScriptWithLlm(creds, budget, summary -> {
                        output.setText(summary);
                        output.setCaretPosition(0);
                        analyzeJs.setEnabled(true);
                        analyze.setEnabled(true);
                    });
        });
        analyzeChains.addActionListener(e -> {
            List<LlmClient.LlmCredential> creds = enabledCredentials();
            if (creds.isEmpty()) { output.setText("[enable an LLM provider and set its key above]"); return; }
            LlmClient.LlmCredential credential = creds.get(0);
            output.setText("Correlating the in-scope finding inventory into exploit chains with "
                    + credential.provider().label() + "... chains will appear as native Burp issues.");
            analyzeChains.setEnabled(false);
            analyze.setEnabled(false);
            controller.analyzeFindingChainsWithLlm(credential, 80, summary -> {
                        output.setText(summary);
                        output.setCaretPosition(0);
                        analyzeChains.setEnabled(true);
                        analyze.setEnabled(true);
                    });
        });
        analyze.addActionListener(e -> {
            String text = input.getText();
            if (text == null || text.isBlank()) { output.setText("[nothing to analyze]"); return; }
            List<LlmClient.LlmCredential> creds = enabledCredentials();
            if (creds.isEmpty()) { output.setText("[enable an LLM provider and set its key above]"); return; }
            LlmClient.LlmCredential credential = creds.get(0);
            output.setText("Analyzing with " + credential.provider().label() + "...");
            analyze.setEnabled(false);
            controller.analyzeWithLlm(credential, system.getText(), text, result -> {
                        output.setText(result);
                        output.setCaretPosition(0);
                        analyze.setEnabled(true);
                    });
        });
        return panel;
    }

    /** AI Nuclei-template authoring tab. Reuses the first enabled provider from the AI analysis tab. */
    private JComponent buildNucleiPanel(ReconController controller) {
        JPanel panel = new JPanel(new BorderLayout(6, 6));

        JTextArea prompt = new JTextArea(6, 80);
        prompt.setLineWrap(true);
        prompt.setWrapStyleWord(true);
        prompt.setToolTipText("Describe the vulnerability / check to turn into a Nuclei template, e.g. "
                + "'detect an exposed Spring Boot actuator /env endpoint' or 'blind SSRF via the url parameter using interactsh'.");
        JTextArea out = new JTextArea(18, 80);
        out.setEditable(false);
        out.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));

        JButton generate = new JButton("Generate Nuclei template");
        JButton save = new JButton("Save .yaml…");
        JButton copy = new JButton("Copy");
        JLabel status = new JLabel("Uses the first enabled provider/model/key from the AI analysis tab. Output is a Nuclei v3 YAML template — review before running with 'nuclei -t'.");

        JPanel top = new JPanel(new BorderLayout(4, 4));
        top.add(new JLabel("Describe the check / vulnerability:"), BorderLayout.NORTH);
        top.add(new JScrollPane(prompt), BorderLayout.CENTER);
        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT));
        bar.add(generate); bar.add(save); bar.add(copy);
        top.add(bar, BorderLayout.SOUTH);

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, top, new JScrollPane(out));
        split.setResizeWeight(0.35);
        panel.add(buildPdcpScanPanel(controller), BorderLayout.NORTH);
        panel.add(split, BorderLayout.CENTER);
        panel.add(status, BorderLayout.SOUTH);

        generate.addActionListener(e -> {
            String desc = prompt.getText();
            if (desc == null || desc.isBlank()) { out.setText("[describe a check first]"); return; }
            List<LlmClient.LlmCredential> creds = enabledCredentials();
            if (creds.isEmpty()) { out.setText("[enable a provider and set its key in the AI analysis tab]"); return; }
            LlmClient.LlmCredential credential = creds.get(0);
            out.setText("Generating a Nuclei template with " + credential.provider().label() + "...");
            generate.setEnabled(false);
            controller.generateNucleiTemplate(credential, desc, result -> {
                out.setText(result);
                out.setCaretPosition(0);
                boolean looksValid = result != null && result.contains("id:") && result.contains("info:")
                        && (result.contains("http:") || result.contains("dns:") || result.contains("ssl:")
                            || result.contains("requests:") || result.contains("code:"));
                status.setText(result != null && result.startsWith("[")
                        ? "Generation failed — check the provider/key in the AI analysis tab."
                        : (looksValid ? "Template generated. Review it, then Save .yaml and run with 'nuclei -t <file>'."
                                      : "Generated, but it may not be a complete Nuclei template — review carefully."));
                generate.setEnabled(true);
            });
        });
        copy.addActionListener(e -> { out.selectAll(); out.copy(); out.select(0, 0); });
        save.addActionListener(e -> saveTemplate(panel, out.getText()));
        return panel;
    }

    /** ProjectDiscovery cloud (PDCP) Nuclei scan controls; results are filed as native Burp issues. */
    private JComponent buildPdcpScanPanel(ReconController controller) {
        JPanel p = new JPanel();
        p.setLayout(new BoxLayout(p, BoxLayout.Y_AXIS));
        p.setBorder(BorderFactory.createTitledBorder(
                "ProjectDiscovery cloud scan (Nuclei) — runs in the cloud, matches import as native Burp issues"));

        JPasswordField pdKey = new JPasswordField(24);
        pdKey.setToolTipText("ProjectDiscovery Cloud API key. Blank = $PDCP_API_KEY. Kept in memory only, never saved.");
        JTextField teamId = new JTextField(8);
        teamId.setToolTipText("Optional X-Team-Id for team-scoped scans.");
        JTextField templates = new JTextField(22);
        templates.setToolTipText("Comma-separated template groups, e.g. cves,exposures,misconfiguration. Blank = recommended.");
        JCheckBox recommended = new JCheckBox("Recommended templates", true);
        JTextArea targets = new JTextArea(3, 44);
        targets.setToolTipText("One target host/URL per line.");
        JButton fill = new JButton("Fill from in-scope");
        JButton run = new JButton("Run cloud scan");
        JLabel pdStatus = new JLabel("Needs a ProjectDiscovery Cloud API key (data is sent to ProjectDiscovery — authorized targets only).");

        JPanel row1 = new JPanel(new FlowLayout(FlowLayout.LEFT));
        row1.add(new JLabel("PDCP key (blank = $PDCP_API_KEY):")); row1.add(pdKey);
        row1.add(new JLabel("Team id:")); row1.add(teamId);
        p.add(row1);

        JPanel row2 = new JPanel(new FlowLayout(FlowLayout.LEFT));
        row2.add(new JLabel("Templates:")); row2.add(templates); row2.add(recommended);
        row2.add(fill); row2.add(run);
        p.add(row2);

        JPanel row3 = new JPanel(new BorderLayout(4, 4));
        row3.add(new JLabel("Targets (one per line):"), BorderLayout.NORTH);
        row3.add(new JScrollPane(targets), BorderLayout.CENTER);
        p.add(row3);
        p.add(pdStatus);

        fill.addActionListener(e -> {
            List<String> t = controller.collectInScopeTargets();
            targets.setText(String.join("\n", t));
            pdStatus.setText("Filled " + t.size() + " in-scope target(s).");
        });
        run.addActionListener(e -> {
            List<String> targetList = new ArrayList<>();
            for (String line : targets.getText().split("\\R")) {
                String v = line.trim();
                if (!v.isEmpty()) targetList.add(v);
            }
            List<String> templateList = new ArrayList<>();
            for (String s : templates.getText().split(",")) {
                String v = s.trim();
                if (!v.isEmpty()) templateList.add(v);
            }
            if (targetList.isEmpty()) { pdStatus.setText("Add at least one target (or click 'Fill from in-scope')."); return; }
            run.setEnabled(false);
            pdStatus.setText("Starting cloud scan…");
            controller.runPdcpScan(new String(pdKey.getPassword()), teamId.getText(), targetList, templateList,
                    recommended.isSelected(), msg -> {
                        pdStatus.setText(msg);
                        if (msg.startsWith("PDCP scan") || msg.startsWith("[error]") || msg.contains("failed")) {
                            run.setEnabled(true);
                        }
                    });
        });
        return p;
    }

    private static void saveTemplate(Component parent, String yaml) {
        if (yaml == null || yaml.isBlank() || yaml.startsWith("[")) {
            JOptionPane.showMessageDialog(parent, "Nothing to save yet — generate a template first.");
            return;
        }
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Save Nuclei template");
        chooser.setSelectedFile(new java.io.File("recon-hound-template.yaml"));
        if (chooser.showSaveDialog(parent) != JFileChooser.APPROVE_OPTION) return;
        try {
            Files.writeString(chooser.getSelectedFile().toPath(), yaml);
            JOptionPane.showMessageDialog(parent, "Saved template to\n" + chooser.getSelectedFile());
        } catch (IOException ex) {
            JOptionPane.showMessageDialog(parent, "Save failed: " + ex.getMessage(),
                    "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    /** Findings tab with SARIF / Markdown export, plus on-demand LLM false-positive triage. */
    private JComponent buildFindingsPanel(ReconController controller, JTable table) {
        JPanel panel = new JPanel(new BorderLayout(4, 4));
        panel.add(new JScrollPane(table), BorderLayout.CENTER);

        JButton exportSarif = new JButton("Export SARIF…");
        JButton exportMarkdown = new JButton("Export Markdown…");
        JSpinner triageBudget = new JSpinner(new SpinnerNumberModel(60, 1, 500, 10));
        JButton triage = new JButton("Triage findings (AI)");
        triage.setToolTipText("Sends not-yet-triaged findings to the enabled LLM provider(s) (see the AI analysis tab) "
                + "to judge false-positive likelihood, and fills in the \"AI Triage\" column. With more than one "
                + "provider enabled, each finding's verdict is a majority vote across them.");
        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT));
        bar.add(exportSarif);
        bar.add(exportMarkdown);
        bar.add(new JLabel("Exports Recon Hound's audit issues for CI ingestion / a bug-bounty writeup."));
        bar.add(new JLabel("  |  Triage batch size:"));
        bar.add(triageBudget);
        bar.add(triage);
        panel.add(bar, BorderLayout.SOUTH);

        exportSarif.addActionListener(e -> exportReport(panel, controller, true));
        exportMarkdown.addActionListener(e -> exportReport(panel, controller, false));
        triage.addActionListener(e -> {
            List<LlmClient.LlmCredential> creds = enabledCredentials();
            if (creds.isEmpty()) {
                JOptionPane.showMessageDialog(panel, "Enable an LLM provider and set its key in the AI analysis tab first.");
                return;
            }
            triage.setEnabled(false);
            controller.triageFindings(creds, (Integer) triageBudget.getValue(), summary -> {
                triage.setEnabled(true);
                JOptionPane.showMessageDialog(panel, summary);
            });
        });
        return panel;
    }

    private static void exportReport(Component parent, ReconController controller, boolean sarif) {
        java.util.List<burp.api.montoya.scanner.audit.issues.AuditIssue> issues = controller.reconIssues();
        if (issues.isEmpty()) {
            JOptionPane.showMessageDialog(parent, "No Recon Hound issues to export yet.");
            return;
        }
        String content = sarif ? ReportExporter.toSarif(issues) : ReportExporter.toMarkdown(issues);
        String defaultName = sarif ? "recon-hound.sarif" : "recon-hound-findings.md";
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle(sarif ? "Save SARIF report" : "Save Markdown report");
        chooser.setSelectedFile(new java.io.File(defaultName));
        if (chooser.showSaveDialog(parent) != JFileChooser.APPROVE_OPTION) return;
        try {
            Files.writeString(chooser.getSelectedFile().toPath(), content);
            JOptionPane.showMessageDialog(parent, "Exported " + issues.size() + " issue(s) to\n" + chooser.getSelectedFile());
        } catch (IOException ex) {
            JOptionPane.showMessageDialog(parent, "Export failed: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private static JPanel buildAssetPanel(ReconController controller, JTable table, ReconModel.AssetTableModel model) {
        JPanel panel = new JPanel(new BorderLayout(4, 4));
        panel.add(new JScrollPane(table), BorderLayout.CENTER);

        JButton export = new JButton("Export…");
        JButton addScope = new JButton("Add all to scope");
        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT));
        bar.add(export);
        bar.add(addScope);
        bar.add(new JLabel("Exports hosts.txt / ips.txt / assets.txt to a chosen folder."));
        panel.add(bar, BorderLayout.SOUTH);

        export.addActionListener(e -> exportAssets(panel, model));
        addScope.addActionListener(e -> {
            int count = controller.addAllAssetsToScope();
            JOptionPane.showMessageDialog(panel, "Added " + count + " host/IP asset(s) to Burp scope.");
        });
        return panel;
    }

    private static void exportAssets(Component parent, ReconModel.AssetTableModel model) {
        List<ReconModel.AssetRow> rows = model.snapshot();
        if (rows.isEmpty()) {
            JOptionPane.showMessageDialog(parent, "No hosts/IPs collected yet.");
            return;
        }
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Choose export folder");
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        if (chooser.showSaveDialog(parent) != JFileChooser.APPROVE_OPTION) return;

        Path dir = chooser.getSelectedFile().toPath();
        TreeSet<String> hosts = new TreeSet<>();
        TreeSet<String> ips = new TreeSet<>();
        TreeSet<String> all = new TreeSet<>();
        for (ReconModel.AssetRow row : rows) {
            all.add(row.value());
            if ("host".equals(row.type())) hosts.add(row.value());
            else ips.add(row.value());
        }
        try {
            Files.write(dir.resolve("hosts.txt"), new ArrayList<>(hosts));
            Files.write(dir.resolve("ips.txt"), new ArrayList<>(ips));
            Files.write(dir.resolve("assets.txt"), new ArrayList<>(all));
            JOptionPane.showMessageDialog(parent,
                    "Wrote hosts.txt (" + hosts.size() + "), ips.txt (" + ips.size()
                            + "), assets.txt (" + all.size() + ") to\n" + dir);
        } catch (IOException ex) {
            JOptionPane.showMessageDialog(parent, "Export failed: " + ex.getMessage(),
                    "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private static JTable buildVectorReferenceTable() {
        DefaultTableModel model = new DefaultTableModel(
                new Object[]{"Applies to", "Vector", "Payload", "Requires", "Technique / bypass note"}, 0) {
            @Override public boolean isCellEditable(int row, int column) { return false; }
        };
        for (XssVectorLibrary.Vector vector : XssVectorLibrary.all()) {
            String requires = vector.requires() == null || vector.requires().isBlank() ? "—" : vector.requires();
            model.addRow(new Object[]{
                    vector.contextLabel(), vector.title(), vector.rendered(), requires, vector.note()
            });
        }
        JTable table = new JTable(model);
        table.setAutoCreateRowSorter(true);
        table.setToolTipText("Curated from the PortSwigger XSS cheat sheet. Copy a payload; nothing is fired automatically.");
        return table;
    }
}
