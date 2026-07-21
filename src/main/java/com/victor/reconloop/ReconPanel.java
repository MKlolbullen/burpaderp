package com.victor.reconloop;

import burp.api.montoya.MontoyaApi;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;

final class ReconPanel extends JPanel {
    private JTabbedPane tabs;
    private Component aiTab;
    private JComboBox<LlmProvider> aiProvider;
    private JTextField aiModel;
    private JPasswordField aiKey;
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
        JButton runActive = new JButton("Run active tests on in-scope site map");

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
        activePanel.add(activeRow3);

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
        tabs.addTab("Findings", new JScrollPane(findings));
        tabs.addTab("Discovered resources", new JScrollPane(discoveries));
        tabs.addTab("Insertion points", new JScrollPane(parameters));
        tabs.addTab("XSS reflections", new JScrollPane(reflectionTable));
        tabs.addTab("Active tests", new JScrollPane(activeTable));
        tabs.addTab("Hosts / IPs", new JScrollPane(assetTable));
        tabs.addTab("XSS vector library", new JScrollPane(vectorTable));
        aiTab = buildAiPanel(controller);
        tabs.addTab("AI analysis", aiTab);
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
        runActive.addActionListener(e -> controller.runActiveTests());
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

    private JPanel buildAiPanel(ReconController controller) {
        JPanel panel = new JPanel(new BorderLayout(6, 6));

        JComboBox<LlmProvider> provider = new JComboBox<>(LlmProvider.values());
        JTextField model = new JTextField(((LlmProvider) provider.getSelectedItem()).defaultModel(), 22);
        JPasswordField apiKey = new JPasswordField(26);
        apiKey.setToolTipText("Leave blank to use the provider's environment variable; kept in memory only, never saved.");
        JButton analyze = new JButton("Analyze");
        JButton clearKey = new JButton("Clear key");
        this.aiProvider = provider;
        this.aiModel = model;
        this.aiKey = apiKey;
        this.aiAnalyze = analyze;

        provider.addActionListener(e -> {
            LlmProvider p = (LlmProvider) provider.getSelectedItem();
            if (p != null) model.setText(p.defaultModel());
        });

        JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT));
        top.add(new JLabel("Provider:")); top.add(provider);
        top.add(new JLabel("Model:")); top.add(model);
        top.add(new JLabel("API key (blank = $ENV):")); top.add(apiKey); top.add(clearKey);
        top.add(analyze);

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

        JLabel privacy = new JLabel("Manual only — nothing is sent until you click Analyze. Data leaves Burp to a third party.");

        panel.add(top, BorderLayout.NORTH);
        panel.add(split, BorderLayout.CENTER);
        panel.add(privacy, BorderLayout.SOUTH);

        clearKey.addActionListener(e -> apiKey.setText(""));
        analyze.addActionListener(e -> {
            String text = input.getText();
            if (text == null || text.isBlank()) { output.setText("[nothing to analyze]"); return; }
            LlmProvider p = (LlmProvider) provider.getSelectedItem();
            output.setText("Analyzing with " + (p == null ? "?" : p.label()) + "...");
            analyze.setEnabled(false);
            controller.analyzeWithLlm(p, model.getText(), new String(apiKey.getPassword()),
                    system.getText(), text, result -> {
                        output.setText(result);
                        output.setCaretPosition(0);
                        analyze.setEnabled(true);
                    });
        });
        return panel;
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
