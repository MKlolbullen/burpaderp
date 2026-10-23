package com.victor.reconloop;

import burp.api.montoya.MontoyaApi;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

final class ReconPanel extends JPanel {
    /** One configurable row per {@link LlmProvider} — enabling several at once lets JS bug-hunting and
     *  triage fan out across providers concurrently instead of being limited to a single active one. */
    private record CredentialRow(LlmProvider provider, JCheckBox enabled, JTextField model, JPasswordField key) {}

    private JTabbedPane tabs;
    private Component aiTab;
    private Component domainReconTab;
    private List<CredentialRow> credentialRows;
    private AiAnalysisPanel aiReview;
    private JTabbedPane aiModes;

    // Agent-team activity tab
    private Component agentTeamTab;
    private EvidenceAgentPanel evidenceAgents;
    private JTabbedPane agentTeamModes;
    private ReconModel.AgentActivityTableModel agentActivityModel;
    private JLabel agentDecision;
    private JTextArea agentSynthesis;
    private JTextArea agentEscalations;
    private JLabel agentUsage;

    // Global AI feed tab
    private ReconModel.AiFeedTableModel aiFeedModel;
    private JLabel aiFeedUsage;

    private void showRequestPreview(JButton button, java.util.function.Supplier<String> preview) {
        button.setEnabled(false);
        new SwingWorker<String, Void>() {
            protected String doInBackground() { return preview.get(); }
            protected void done() {
                button.setEnabled(true);
                String result;
                try { result = get(); }
                catch (Exception e) { result = "Could not prepare this request preview. No requests sent."; }
                JTextArea text = new JTextArea(result, 24, 100);
                text.setEditable(false);
                text.setCaretPosition(0);
                JOptionPane.showMessageDialog(ReconPanel.this, new JScrollPane(text), "Request preview", JOptionPane.INFORMATION_MESSAGE);
            }
        }.execute();
    }

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
        JButton crawlPreview = new JButton("Preview seeds / crawl queue…");
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
        buttons.add(addSeeds); buttons.add(queueSiteMap); buttons.add(crawlPreview); buttons.add(pause); buttons.add(resume); buttons.add(reset);
        controls.add(buttons);

        JLabel payloads = new JLabel("Payload categories: " + controller.payloadCategories());
        controls.add(payloads);

        JTextField osintDomain = new JTextField(18);
        JButton osintButton = new JButton("Look up hosts");
        osintButton.setToolTipText("Queries Shodan, Censys, VirusTotal, and FOFA for this domain. "
                + "No request is sent to the target. Keys: $SHODAN_API_KEY, $CENSYS_API_TOKEN, "
                + "$VIRUSTOTAL_API_KEY, $FOFA_API_KEY. Keys are not stored.");
        JPanel osintPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        osintPanel.setBorder(BorderFactory.createTitledBorder(
                "Passive OSINT — public scan and DNS data only (no traffic to the target)"));
        osintPanel.add(new JLabel("Domain:"));
        osintPanel.add(osintDomain);
        osintPanel.add(osintButton);
        osintPanel.add(new JLabel("Shodan, Censys, VirusTotal, FOFA. Missing keys are skipped."));
        controls.add(osintPanel);

        // ---- Active testing (opt-in) ----
        JCheckBox activeEnabled = new JCheckBox("Enable active tests (fires payloads — authorized targets only)", false);
        JCheckBox mutatingActive = new JCheckBox("Allow mutating active replays (POST/PUT/PATCH/DELETE)", false);
        mutatingActive.setToolTipText("Default active tests replay only GET/HEAD/OPTIONS. Enable only when state-changing requests are explicitly authorized.");
        JCheckBox oastActive = new JCheckBox("Allow OAST / Collaborator callbacks", false);
        JCheckBox persistentPayloadActive = new JCheckBox("Allow persistent / stored browser payloads", false);
        JCheckBox timeDelayActive = new JCheckBox("Allow time-delay probes", false);
        JCheckBox uploadActive = new JCheckBox("Allow upload mutations", false);
        JCheckBox authLockoutActive = new JCheckBox("Allow auth / lockout probes", false);
        oastActive.setToolTipText("Allows Collaborator-backed payloads. Blind-XSS also requires the separate persistent / stored browser payload grant.");
        persistentPayloadActive.setToolTipText("Browser payloads may be stored and execute later. Blind-XSS requires both this grant and OAST; non-safe methods require the mutating replay grant too.");
        timeDelayActive.setToolTipText("Required before SLEEP/PG_SLEEP/WAITFOR-style timing payloads are dispatched.");
        uploadActive.setToolTipText("Required before multipart upload filenames/bodies are actively replayed.");
        authLockoutActive.setToolTipText("Required before rate-limit, JWT forgery, or alternate-identity access-control replays are dispatched.");
        JSpinner activeBudget = new JSpinner(new SpinnerNumberModel(60, 1, 5000, 10));
        JSpinner activeHostBudget = new JSpinner(new SpinnerNumberModel(60, 1, 5000, 10));
        JSpinner activeEndpointBudget = new JSpinner(new SpinnerNumberModel(20, 1, 5000, 5));
        JSpinner activeProbeBudget = new JSpinner(new SpinnerNumberModel(20, 1, 5000, 5));
        activeHostBudget.setToolTipText("Maximum target-directed requests to one host during a run.");
        activeEndpointBudget.setToolTipText("Maximum requests to one HTTP method + path during a run; query mutations share the same endpoint quota.");
        activeProbeBudget.setToolTipText("Maximum requests attributed to one probe ID during a run.");
        JTextField ctDomain = new JTextField(18);
        JButton ctButton = new JButton("Enumerate (crt.sh)");
        JTextField paramUrl = new JTextField(22);
        JButton paramButton = new JButton("Discover params (Arjun)");
        JButton paramPreview = new JButton("Preview params…");
        JTextField graphqlUrl = new JTextField(22);
        JButton graphqlButton = new JButton("Introspect GraphQL");
        JButton graphqlFuzzButton = new JButton("Fuzz GraphQL");
        JButton graphqlPreview = new JButton("Preview introspection…");
        JButton graphqlFuzzPreview = new JButton("Preview GraphQL fuzz…");
        JButton runActive = new JButton("Run active tests on in-scope site map");
        JButton activePreview = new JButton("Preview native probes…");
        JComboBox<String> previewProbe = new JComboBox<>(new String[]{"All probes", "waf", "reflected-xss", "ssti", "ssrf", "blind-xss",
                "command-injection", "open-redirect", "crlf", "sqli", "nosqli", "path-traversal", "host-header", "cors", "rate-limit", "file-upload", "xxe"});
        previewProbe.setToolTipText("Filter preview detail to one probe when the 500-step limit truncates the full plan.");
        JButton runJwt = new JButton("Run JWT alg:none test");
        JButton runTakeover = new JButton("Subdomain takeover check");
        JButton jwtPreview = new JButton("Preview JWT…");
        JButton takeoverPreview = new JButton("Preview takeover…");
        JButton importSidecar = new JButton("Import reconctl JSONL…");
        importSidecar.setToolTipText("Imports typed Go-sidecar results after re-checking every record against the current Burp scope. Does not launch a tool or send traffic.");

        JPanel activePanel = new JPanel();
        activePanel.setLayout(new BoxLayout(activePanel, BoxLayout.Y_AXIS));
        activePanel.setBorder(BorderFactory.createTitledBorder("Active testing (opt-in) — SSRF / SSTI / XSS via Burp Collaborator"));

        JPanel activeRow1 = new JPanel(new FlowLayout(FlowLayout.LEFT));
        activeRow1.add(activeEnabled);
        activeRow1.add(mutatingActive);
        activeRow1.add(new JLabel("Global run budget:")); activeRow1.add(activeBudget);
        activeRow1.add(runActive);
        activePanel.add(activeRow1);

        JPanel quotaRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        quotaRow.add(new JLabel("Per-host:")); quotaRow.add(activeHostBudget);
        quotaRow.add(new JLabel("Per-endpoint:")); quotaRow.add(activeEndpointBudget);
        quotaRow.add(new JLabel("Per-probe:")); quotaRow.add(activeProbeBudget);
        quotaRow.add(new JLabel("(effective values are capped by the global run budget)"));
        activePanel.add(quotaRow);

        JPanel riskRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        riskRow.add(new JLabel("Risk permissions:"));
        riskRow.add(oastActive);
        riskRow.add(timeDelayActive);
        riskRow.add(uploadActive);
        riskRow.add(authLockoutActive);
        activePanel.add(riskRow);
        JPanel persistentRiskRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        persistentRiskRow.add(persistentPayloadActive);
        persistentRiskRow.add(new JLabel("Blind-XSS needs this and OAST. Destructive corpus entries remain disabled."));
        activePanel.add(persistentRiskRow);
        JPanel previewRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        previewRow.add(new JLabel("Native probe dry run:")); previewRow.add(previewProbe); previewRow.add(activePreview);
        previewRow.add(new JLabel("(no traffic; response branches and runtime templates are identified)"));
        activePanel.add(previewRow);

        JPanel activeRow2 = new JPanel(new FlowLayout(FlowLayout.LEFT));
        activeRow2.add(new JLabel("crt.sh domain:")); activeRow2.add(ctDomain); activeRow2.add(ctButton);
        activeRow2.add(new JLabel("Param-discovery URL:")); activeRow2.add(paramUrl); activeRow2.add(paramButton);
        activeRow2.add(paramPreview);
        activeRow2.add(new JLabel("Param wordlist: " + controller.paramWordlistSize()));
        activePanel.add(activeRow2);

        JPanel activeRow3 = new JPanel(new FlowLayout(FlowLayout.LEFT));
        activeRow3.add(new JLabel("GraphQL URL:")); activeRow3.add(graphqlUrl); activeRow3.add(graphqlButton);
        activeRow3.add(graphqlFuzzButton);
        activeRow3.add(graphqlPreview);
        activeRow3.add(graphqlFuzzPreview);
        activePanel.add(activeRow3);

        JPanel activeRow4 = new JPanel(new FlowLayout(FlowLayout.LEFT));
        activeRow4.add(runJwt); activeRow4.add(jwtPreview);
        activeRow4.add(runTakeover); activeRow4.add(takeoverPreview);
        activeRow4.add(new JLabel("(opt-in — JWT replays GET/HEAD/OPTIONS; takeover fetches enumerated hosts)"));
        activePanel.add(activeRow4);

        JPanel sidecarRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        sidecarRow.add(importSidecar);
        sidecarRow.add(new JLabel("Import contract-validated reconctl JSONL (scope is checked again; no target traffic is sent)."));
        activePanel.add(sidecarRow);

        // Corpus fuzz: fires the (otherwise-dormant) payloads/*.txt corpus in one or more encodings.
        JCheckBox encRaw = new JCheckBox("Raw", true);
        JCheckBox encUrl = new JCheckBox("URL", false);
        JCheckBox encHtml = new JCheckBox("HTML", false);
        JCheckBox encBase64 = new JCheckBox("Base64", false);
        JCheckBox encDoubleUrl = new JCheckBox("Double URL", false);
        JCheckBox encB64Url = new JCheckBox("Base64->URL", false);
        JCheckBox encUrlB64 = new JCheckBox("URL->Base64", false);
        JSpinner corpusBudget = new JSpinner(new SpinnerNumberModel(5, 1, 200, 1));
        JButton runCorpusFuzz = new JButton("Run corpus fuzz on in-scope site map");
        JButton corpusPreview = new JButton("Preview corpus…");
        JComboBox<String> corpusPreviewCategory = new JComboBox<>(new String[]{"All categories", "sqli", "sqli2", "xss", "ssti", "lfi", "rce_payloads"});
        corpusPreviewCategory.setToolTipText("Preview one category beyond the 500-step prefix; execution still uses all relevant categories.");
        JPanel corpusRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        corpusRow.add(new JLabel("Corpus fuzz encodings:"));
        corpusRow.add(encRaw); corpusRow.add(encUrl); corpusRow.add(encHtml); corpusRow.add(encBase64);
        corpusRow.add(encDoubleUrl); corpusRow.add(encB64Url); corpusRow.add(encUrlB64);
        corpusRow.add(new JLabel("Max payloads/category:")); corpusRow.add(corpusBudget);
        corpusRow.add(runCorpusFuzz); corpusRow.add(corpusPreviewCategory); corpusRow.add(corpusPreview);
        activePanel.add(corpusRow);
        activePanel.add(new JLabel("(fires payloads/*.txt: LFI/RCE/SQLi/SSTI/XSS corpus at heuristically-matched "
                + "parameters; destructive entries are skipped, callback hosts are rewritten to Collaborator)"));

        activePanel.add(new JLabel("sqlmap execution is paused; use the native SQLi probes."));

        // Access-control / IDOR (Autorize-style)
        JTextArea acHeaders = new JTextArea(2, 60);
        acHeaders.setToolTipText("Alternate identity headers, one per line, e.g. 'Cookie: session=lowpriv' or 'Authorization: Bearer ...'");
        JCheckBox acUnauth = new JCheckBox("Unauthenticated (strip auth)", false);
        JButton acButton = new JButton("Run access-control test (safe methods)");
        JButton acPreview = new JButton("Preview access-control…");
        JPanel acRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        acRow.add(new JLabel("Access-control alternate identity:"));
        acRow.add(new JScrollPane(acHeaders));
        acRow.add(acUnauth);
        acRow.add(acButton); acRow.add(acPreview);
        activePanel.add(acRow);
        controls.add(activePanel);

        JLabel status = new JLabel(controller.status());
        JToggleButton scanControls = new JToggleButton("Hide scan controls", true);
        JPanel scanHeader = new JPanel(new BorderLayout(4, 4));
        JPanel scanStatus = new JPanel(new BorderLayout(8, 0));
        scanStatus.add(scanControls, BorderLayout.WEST); scanStatus.add(status);
        scanHeader.add(scanStatus, BorderLayout.NORTH); scanHeader.add(controls);
        scanControls.addActionListener(e -> {
            controls.setVisible(scanControls.isSelected());
            scanControls.setText(scanControls.isSelected() ? "Hide scan controls" : "Show scan controls");
            revalidate();
        });
        add(scanHeader, BorderLayout.NORTH);

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
        JPanel activeResults = new JPanel(new BorderLayout());
        activeResults.add(new JScrollPane(activeTable), BorderLayout.CENTER);
        JButton viewEvidence = new JButton("View evidence…");
        viewEvidence.addActionListener(event -> {
            int selected = activeTable.getSelectedRow();
            if (selected < 0) return;
            ReconModel.ActiveRow row = activeModel.row(activeTable.convertRowIndexToModel(selected));
            JTabbedPane evidenceTabs = new JTabbedPane();
            JTextArea summary = new JTextArea(row.evidenceRecord().describe(), 24, 100); summary.setEditable(false);
            JTextArea json = new JTextArea(Json.write(ActiveEvidenceCodec.rowMap(row)), 24, 100); json.setEditable(false);
            evidenceTabs.addTab("Summary", new JScrollPane(summary));
            evidenceTabs.addTab("JSON / exact captured bytes (Base64)", new JScrollPane(json));
            JOptionPane.showMessageDialog(this, evidenceTabs, "Finding evidence", JOptionPane.PLAIN_MESSAGE);
        });
        activeResults.add(viewEvidence, BorderLayout.SOUTH);
        tabs.addTab("Active tests", activeResults);
        tabs.addTab("Hosts / IPs", buildAssetPanel(controller, assetTable, assetModel));
        domainReconTab = new DomainReconPanel(controller::enumerateDomain, controller::importSidecarJsonl,
                sources->stageAiSources(sources,"Review the captured recon requests/responses and JavaScript for source-anchored vulnerability candidates and manual PoC suggestions."));
        tabs.addTab("Recon chain", domainReconTab);
        tabs.addTab("XSS vector library", new JScrollPane(vectorTable));
        aiTab = buildAiPanel(controller);
        tabs.addTab("AI analysis", aiTab);
        agentTeamTab = buildAgentTeamPanel(controller);
        tabs.addTab("Agent team", agentTeamTab);
        tabs.addTab("AI feed", buildAiFeedPanel(controller));
        tabs.addTab("Nuclei templates (AI)", buildNucleiPanel(controller));
        tabs.addChangeListener(e -> {
            boolean show = tabs.getSelectedComponent() != aiTab && tabs.getSelectedComponent() != agentTeamTab
                    && tabs.getSelectedComponent() != domainReconTab;
            scanControls.setSelected(show); controls.setVisible(show);
            scanControls.setText(show ? "Hide scan controls" : "Show scan controls");
            revalidate();
        });
        add(tabs, BorderLayout.CENTER);

        // Every LLM touchpoint streams into the AI feed; the controller delivers events on the EDT.
        controller.setAiFeedListener(event -> {
            aiFeedModel.add(event);
            aiFeedUsage.setText(AiFeed.summarize(controller.aiFeedSnapshot()));
        });

        autoLoop.addActionListener(e -> controller.setCrawlEnabled(autoLoop.isSelected()));
        addScope.addActionListener(e -> controller.setAddToScope(addScope.isSelected()));
        sameOrigin.addActionListener(e -> controller.setSameOriginOnly(sameOrigin.isSelected()));
        includeInfo.addActionListener(e -> controller.setIncludeInfoFindings(includeInfo.isSelected()));
        gfPatterns.addActionListener(e -> controller.setScanGfPatterns(gfPatterns.isSelected()));
        redirects.addActionListener(e -> controller.setFollowRedirects(redirects.isSelected()));
        reflections.addActionListener(e -> controller.setDetectReflections(reflections.isSelected()));
        activeEnabled.addActionListener(e -> controller.setActiveTestsEnabled(activeEnabled.isSelected()));
        mutatingActive.addActionListener(e -> controller.setMutatingActiveRequests(mutatingActive.isSelected()));
        oastActive.addActionListener(e -> controller.setOastActiveRequests(oastActive.isSelected()));
        persistentPayloadActive.addActionListener(e -> controller.setPersistentPayloadActiveRequests(persistentPayloadActive.isSelected()));
        timeDelayActive.addActionListener(e -> controller.setTimeDelayActiveRequests(timeDelayActive.isSelected()));
        uploadActive.addActionListener(e -> controller.setUploadActiveRequests(uploadActive.isSelected()));
        authLockoutActive.addActionListener(e -> controller.setAuthLockoutActiveRequests(authLockoutActive.isSelected()));
        activeBudget.addChangeListener(e -> controller.setActiveRequestBudget((Integer) activeBudget.getValue()));
        activeHostBudget.addChangeListener(e -> controller.setActivePerHostBudget((Integer) activeHostBudget.getValue()));
        activeEndpointBudget.addChangeListener(e -> controller.setActivePerEndpointBudget((Integer) activeEndpointBudget.getValue()));
        activeProbeBudget.addChangeListener(e -> controller.setActivePerProbeBudget((Integer) activeProbeBudget.getValue()));
        osintButton.addActionListener(e -> controller.lookupPassiveOsint(osintDomain.getText()));
        ctButton.addActionListener(e -> controller.enumerateSubdomains(ctDomain.getText()));
        paramButton.addActionListener(e -> controller.discoverParameters(paramUrl.getText()));
        paramPreview.addActionListener(e -> {
            String target = paramUrl.getText();
            showRequestPreview(paramPreview, () -> controller.previewRequests(target, ReconController.PreviewAction.PARAMETERS));
        });
        graphqlPreview.addActionListener(e -> {
            String target = graphqlUrl.getText();
            showRequestPreview(graphqlPreview, () -> controller.previewRequests(target, ReconController.PreviewAction.GRAPHQL_INTROSPECTION));
        });
        graphqlFuzzPreview.addActionListener(e -> {
            String target = graphqlUrl.getText();
            showRequestPreview(graphqlFuzzPreview, () -> controller.previewRequests(target, ReconController.PreviewAction.GRAPHQL_FUZZ));
        });
        activePreview.addActionListener(e -> {
            String filter = previewProbe.getSelectedIndex() == 0 ? null : (String) previewProbe.getSelectedItem();
            showRequestPreview(activePreview, () -> controller.previewActiveTests(filter));
        });
        jwtPreview.addActionListener(e -> showRequestPreview(jwtPreview, controller::previewJwtAttacks));
        takeoverPreview.addActionListener(e -> showRequestPreview(takeoverPreview, controller::previewTakeover));
        crawlPreview.addActionListener(e -> {
            String text = seeds.getText();
            showRequestPreview(crawlPreview, () -> controller.previewCrawl(text));
        });
        acPreview.addActionListener(e -> {
            String headers = acHeaders.getText(); boolean unauthenticated = acUnauth.isSelected();
            showRequestPreview(acPreview, () -> controller.previewAccessControl(headers, unauthenticated));
        });
        graphqlButton.addActionListener(e -> controller.introspectGraphql(graphqlUrl.getText()));
        graphqlFuzzButton.addActionListener(e -> controller.fuzzGraphql(graphqlUrl.getText()));
        runActive.addActionListener(e -> controller.runActiveTests());
        runJwt.addActionListener(e -> controller.runJwtAttacks());
        runTakeover.addActionListener(e -> controller.runSubdomainTakeoverCheck());
        importSidecar.addActionListener(e -> {
            JFileChooser chooser = new JFileChooser();
            chooser.setDialogTitle("Import reconctl JSONL");
            if (chooser.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) return;
            importSidecar.setEnabled(false);
            controller.importSidecarJsonl(chooser.getSelectedFile().toPath(), summary -> {
                importSidecar.setEnabled(true);
                JOptionPane.showMessageDialog(this, summary, "reconctl import",
                        summary.startsWith("[error]") ? JOptionPane.ERROR_MESSAGE : JOptionPane.INFORMATION_MESSAGE);
            });
        });
        java.util.function.Supplier<Set<PayloadEncoder.Encoding>> selectedEncodings = () -> {
            Set<PayloadEncoder.Encoding> encodings = EnumSet.noneOf(PayloadEncoder.Encoding.class);
            if (encRaw.isSelected()) encodings.add(PayloadEncoder.Encoding.RAW);
            if (encUrl.isSelected()) encodings.add(PayloadEncoder.Encoding.URL);
            if (encHtml.isSelected()) encodings.add(PayloadEncoder.Encoding.HTML);
            if (encBase64.isSelected()) encodings.add(PayloadEncoder.Encoding.BASE64);
            if (encDoubleUrl.isSelected()) encodings.add(PayloadEncoder.Encoding.DOUBLE_URL);
            if (encB64Url.isSelected()) encodings.add(PayloadEncoder.Encoding.BASE64_THEN_URL);
            if (encUrlB64.isSelected()) encodings.add(PayloadEncoder.Encoding.URL_THEN_BASE64);
            return encodings;
        };
        runCorpusFuzz.addActionListener(e -> controller.runCorpusFuzz(selectedEncodings.get(), (Integer) corpusBudget.getValue()));
        corpusPreview.addActionListener(e -> {
            Set<PayloadEncoder.Encoding> encodings = selectedEncodings.get(); int cap = (Integer) corpusBudget.getValue();
            String category = corpusPreviewCategory.getSelectedIndex() == 0 ? null : (String) corpusPreviewCategory.getSelectedItem();
            showRequestPreview(corpusPreview, () -> controller.previewCorpusFuzz(encodings, cap, category));
        });
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

    /** Stage content locally; context-menu actions never trigger a provider call. */
    void stageAiSources(List<AiAnalysis.Source> sources, String reviewFocus) {
        if (aiReview == null) return;
        SwingUtilities.invokeLater(() -> {
            if (aiTab != null) tabs.setSelectedComponent(aiTab);
            aiModes.setSelectedComponent(aiReview);
            try {
                for (var source : sources) aiReview.stage(source.kind(), source.name(), source.text());
                aiReview.focus.setText(reviewFocus == null ? "" : reviewFocus);
            } catch (IllegalArgumentException ex) { aiReview.showMessage(ex.getMessage()); }
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

    /**
     * Derives an {@link AgentTeam.AgentSpec} per enabled provider using default role/effort/budget:
     * each provider takes the role it is the natural default for, high effort, and a standard token
     * budget. The richer per-provider role/effort/budget UI is a later slice; this lets the team run
     * on the existing credential rows today.
     */
    private List<AgentTeam.AgentSpec> enabledAgentSpecs() {
        List<AgentTeam.AgentSpec> out = new ArrayList<>();
        for (LlmClient.LlmCredential cred : enabledCredentials()) {
            out.add(new AgentTeam.AgentSpec(AgentRole.defaultRoleFor(cred.provider()), cred.provider(),
                    cred.model(), cred.apiKey(), ReasoningEffort.HIGH, 8000));
        }
        return out;
    }

    private JPanel buildAiPanel(ReconController controller) {
        JPanel panel = new JPanel(new BorderLayout(6, 6));

        JButton analyze = new JButton("Analyze");
        JButton clearKeys = new JButton("Clear entered keys");
        JSpinner jsBudget = new JSpinner(new SpinnerNumberModel(15, 1, 500, 5));
        JButton analyzeJs = new JButton("Analyze in-scope JS → Burp issues");
        analyzeJs.setToolTipText("Sends in-scope JavaScript from the site map to the enabled LLM provider(s), "
                + "up to the file budget, and files each structured finding (bug + PoC + chain) as a native Burp issue. "
                + "With more than one provider enabled, files are round-robined across them concurrently.");
        JButton analyzeChains = new JButton("Chain findings → exploit chains");
        analyzeChains.setToolTipText("Sends the in-scope finding inventory (all audit issues) to the first enabled LLM provider "
                + "and files ranked exploit chains (writeup + reproducible steps) as native Burp issues.");
        JButton runTeam = new JButton("Run agent team (findings)");
        runTeam.setToolTipText("Runs the enabled providers as a team over the in-scope finding inventory: recon "
                + "prioritises, a drafter reasons a PoC on paper, a different-provider verifier attacks it, and the "
                + "most powerful provider leads and synthesises. Anything that would touch the target is held as a "
                + "human-approval escalation. Makes LLM calls only — no target traffic is sent.");

        List<CredentialRow> rows = new ArrayList<>();
        JPanel providersPanel = new JPanel(new GridLayout(0, 1, 2, 2));
        providersPanel.setBorder(BorderFactory.createTitledBorder(
                "LLM providers — enable one or more; multiple run together (JS bug-hunt throughput, triage ensemble voting)"));
        for (LlmProvider p : LlmProvider.values()) {
            JCheckBox enabled = new JCheckBox(p.label());
            JTextField model = new JTextField(p.configuredModel(System::getenv), 16);
            model.setToolTipText("Initial value from $" + p.modelEnvVar() + " or the built-in default; enter a model available to your account.");
            JPasswordField key = new JPasswordField(18);
            key.setToolTipText("Leave blank to use $" + p.envVar() + "; kept in memory only, never saved.");
            JPanel row = new JPanel(new FlowLayout(FlowLayout.LEFT));
            row.add(enabled);
            row.add(new JLabel("Model:")); row.add(model);
            row.add(new JLabel("Key ($" + p.envVar() + "):")); row.add(key);
            providersPanel.add(row);
            rows.add(new CredentialRow(p, enabled, model, key));
        }
        this.credentialRows = rows;
        this.aiReview = new AiAnalysisPanel(this::enabledCredentials, controller::reviewEvidence);
        javax.swing.event.DocumentListener credentialChanges = new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) { aiReview.credentialsChanged(); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { aiReview.credentialsChanged(); }
            public void changedUpdate(javax.swing.event.DocumentEvent e) { aiReview.credentialsChanged(); }
        };
        for (var row : rows) {
            row.enabled().addActionListener(e -> aiReview.credentialsChanged());
            row.model().getDocument().addDocumentListener(credentialChanges);
            row.key().getDocument().addDocumentListener(credentialChanges);
        }

        JPanel top = new JPanel(new BorderLayout(4, 4));
        top.add(providersPanel, BorderLayout.CENTER);
        JPanel topButtons = new JPanel(new FlowLayout(FlowLayout.LEFT));
        topButtons.add(analyze);
        JPanel keyControls = new JPanel(new FlowLayout(FlowLayout.LEFT));
        keyControls.add(clearKeys);
        keyControls.add(new JLabel("Blank key fields use the named environment variables. Keys are never saved."));
        top.add(keyControls, BorderLayout.SOUTH);

        JPanel jsBar = new JPanel(new FlowLayout(FlowLayout.LEFT));
        jsBar.add(new JLabel("Automated JS bug-hunt — files/run:"));
        jsBar.add(jsBudget);
        jsBar.add(analyzeJs);
        jsBar.add(analyzeChains);
        jsBar.add(runTeam);
        jsBar.add(new JLabel("(on-demand; results become native Burp issues)"));

        JTextArea system = new JTextArea(LlmClient.DEFAULT_JS_SYSTEM_PROMPT, 3, 80);
        system.setLineWrap(true); system.setWrapStyleWord(true);
        JTextArea input = new JTextArea(12, 80);
        input.setToolTipText("Paste JavaScript, recovered source, a response, or a finding to analyze.");
        JTextArea output = new JTextArea(14, 80);
        output.setEditable(false); output.setLineWrap(true); output.setWrapStyleWord(true);

        JPanel prompts = new JPanel(new GridLayout(0, 1, 4, 4));
        prompts.add(new JLabel("System prompt:"));
        prompts.add(new JScrollPane(system));
        prompts.add(new JLabel("Input (sent to the selected third-party LLM — authorized data only):"));
        prompts.add(new JScrollPane(input));

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, prompts, new JScrollPane(output));
        split.setResizeWeight(0.6);

        JPanel promptTools = new JPanel(new BorderLayout(4, 4));
        JPanel existingTools = new JPanel(new GridLayout(0, 1));
        existingTools.add(jsBar); existingTools.add(topButtons);
        existingTools.add(new JLabel("These tools send raw input to the selected providers."));
        promptTools.add(existingTools, BorderLayout.NORTH); promptTools.add(split);
        aiModes = new JTabbedPane();
        aiModes.addTab("Evidence review", aiReview);
        aiModes.addTab("Prompt tools (raw input)", promptTools);

        JLabel privacy = new JLabel("Nothing is sent until you click a button. Data leaves Burp to the selected third-party LLM — authorized data only.");

        JPanel north = new JPanel();
        north.setLayout(new BoxLayout(north, BoxLayout.Y_AXIS));
        north.add(top);
        panel.add(north, BorderLayout.NORTH);
        panel.add(aiModes, BorderLayout.CENTER);
        panel.add(privacy, BorderLayout.SOUTH);

        clearKeys.addActionListener(e -> {
            aiReview.credentialsChanged();
            for (CredentialRow row : rows) row.key().setText("");
        });
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
        runTeam.addActionListener(e -> {
            List<AgentTeam.AgentSpec> specs = enabledAgentSpecs();
            if (specs.isEmpty()) { output.setText("[enable an LLM provider and set its key above]"); return; }
            output.setText("Agent team started across " + specs.size()
                    + " provider(s) — see the \"Agent team\" tab. LLM calls only; no target traffic is sent.");
            agentActivityModel.clear();
            agentDecision.setText("Agent team running over the in-scope finding inventory across " + specs.size() + " provider(s)…");
            agentSynthesis.setText("");
            agentEscalations.setText("");
            agentUsage.setText(" ");
            if (agentTeamTab != null) { tabs.setSelectedComponent(agentTeamTab); agentTeamModes.setSelectedIndex(1); }
            runTeam.setEnabled(false);
            analyze.setEnabled(false);
            controller.runAgentTeam(specs, 60,
                    entry -> agentActivityModel.add(new ReconModel.AgentActivityRow(
                            entry.role().title(), entry.provider().label(), entry.model(), entry.status(),
                            Long.toString(entry.estInputTokens()), Long.toString(entry.estOutputTokens()), entry.summary())),
                    summary -> {
                        agentDecision.setText("Decision: " + summary.decision());
                        agentSynthesis.setText(summary.synthesis());
                        agentSynthesis.setCaretPosition(0);
                        if (summary.escalations().isEmpty()) {
                            agentEscalations.setText("No proposed action needs to touch the target; nothing was sent.");
                        } else {
                            StringBuilder sb = new StringBuilder(summary.escalations().size()
                                    + " proposed action(s) require human approval before any target traffic:\n");
                            for (String esc : summary.escalations()) sb.append("  • ").append(esc).append('\n');
                            agentEscalations.setText(sb.toString());
                        }
                        agentEscalations.setCaretPosition(0);
                        agentUsage.setText(summary.usageText());
                        runTeam.setEnabled(true);
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

    /**
     * The "Agent team" tab: a curated live view of a multi-agent run — the per-round table (fed live as
     * each provider finishes), the leader's decision and synthesis, the human-approval escalation queue,
     * and an estimated-usage meter. Populated by {@link ReconController#runAgentTeam} via the
     * "Run agent team (findings)" button in the AI tab; it makes LLM calls only and sends no target traffic.
     */
    private JComponent buildAgentTeamPanel(ReconController controller) {
        JPanel panel = new JPanel(new BorderLayout(6, 6));

        agentDecision = new JLabel("No agent-team run yet. Enable providers in the AI tab and click \"Run agent team (findings)\".");
        agentUsage = new JLabel(" ");
        JPanel top = new JPanel();
        top.setLayout(new BoxLayout(top, BoxLayout.Y_AXIS));
        top.add(agentDecision);
        top.add(agentUsage);

        agentActivityModel = new ReconModel.AgentActivityTableModel();
        JTable rounds = new JTable(agentActivityModel);
        rounds.setAutoCreateRowSorter(false); // preserve execution order (recon → drafter → verifier → leader)

        agentSynthesis = new JTextArea(12, 80);
        agentSynthesis.setEditable(false); agentSynthesis.setLineWrap(true); agentSynthesis.setWrapStyleWord(true);
        JPanel synthPanel = new JPanel(new BorderLayout(4, 4));
        synthPanel.add(new JLabel("Leader synthesis:"), BorderLayout.NORTH);
        synthPanel.add(new JScrollPane(agentSynthesis), BorderLayout.CENTER);

        agentEscalations = new JTextArea(6, 80);
        agentEscalations.setEditable(false); agentEscalations.setLineWrap(true); agentEscalations.setWrapStyleWord(true);
        JPanel escPanel = new JPanel(new BorderLayout(4, 4));
        escPanel.add(new JLabel("Human-approval queue — proposed steps the team may NOT run itself:"), BorderLayout.NORTH);
        escPanel.add(new JScrollPane(agentEscalations), BorderLayout.CENTER);

        JSplitPane lower = new JSplitPane(JSplitPane.VERTICAL_SPLIT, synthPanel, escPanel);
        lower.setResizeWeight(0.65);
        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(rounds), lower);
        split.setResizeWeight(0.4);

        panel.add(top, BorderLayout.NORTH);
        panel.add(split, BorderLayout.CENTER);
        evidenceAgents = new EvidenceAgentPanel(aiReview::snapshotForTeam, this::enabledCredentials, controller::runEvidenceAgentJobs);
        agentTeamModes = new JTabbedPane();
        agentTeamModes.addTab("Five-agent evidence jobs", evidenceAgents);
        agentTeamModes.addTab("Finding inventory (raw input)", panel);
        aiReview.setTeamPlanner(() -> {
            tabs.setSelectedComponent(agentTeamTab); agentTeamModes.setSelectedIndex(0); evidenceAgents.preparePlan();
        }, evidenceAgents::contextChanged);
        return agentTeamModes;
    }

    /**
     * The "AI feed" tab: one live stream of every LLM touchpoint in the extension — false-positive
     * triage, JavaScript review, exploit chaining, Nuclei-template authoring, agent-team rounds, and
     * the human-approval gate decisions that govern them — newest first, with Kind/Provider filters
     * and a session usage meter. In-memory only: nothing here is written to disk or the proxy history.
     */
    private JComponent buildAiFeedPanel(ReconController controller) {
        JPanel panel = new JPanel(new BorderLayout(6, 6));

        aiFeedModel = new ReconModel.AiFeedTableModel();
        JTable table = new JTable(aiFeedModel);
        table.setAutoCreateRowSorter(false); // model already prepends newest-first
        javax.swing.table.TableRowSorter<ReconModel.AiFeedTableModel> sorter =
                new javax.swing.table.TableRowSorter<>(aiFeedModel);
        sorter.setSortable(0, false); // keep the model's newest-first order; the combos only filter
        table.setRowSorter(sorter);

        JComboBox<String> kindFilter = new JComboBox<>();
        kindFilter.addItem("All kinds");
        for (AiFeed.Kind k : AiFeed.Kind.values()) kindFilter.addItem(k.label());
        JComboBox<String> providerFilter = new JComboBox<>();
        providerFilter.addItem("All providers");
        for (LlmProvider p : LlmProvider.values()) providerFilter.addItem(p.label());

        Runnable applyFilter = () -> {
            String kind = (String) kindFilter.getSelectedItem();
            String provider = (String) providerFilter.getSelectedItem();
            List<javax.swing.RowFilter<Object, Object>> filters = new ArrayList<>();
            if (kind != null && !kind.startsWith("All"))
                filters.add(javax.swing.RowFilter.regexFilter("^" + java.util.regex.Pattern.quote(kind) + "$", 1));
            if (provider != null && !provider.startsWith("All"))
                filters.add(javax.swing.RowFilter.regexFilter("^" + java.util.regex.Pattern.quote(provider) + "$", 2));
            sorter.setRowFilter(filters.isEmpty() ? null : javax.swing.RowFilter.andFilter(filters));
        };
        kindFilter.addActionListener(e -> applyFilter.run());
        providerFilter.addActionListener(e -> applyFilter.run());

        JButton clear = new JButton("Clear feed");
        clear.addActionListener(e -> {
            controller.clearAiFeed();
            aiFeedModel.clear();
            aiFeedUsage.setText(AiFeed.summarize(controller.aiFeedSnapshot()));
        });

        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        toolbar.add(new JLabel("Filter:"));
        toolbar.add(kindFilter);
        toolbar.add(providerFilter);
        toolbar.add(clear);

        aiFeedUsage = new JLabel("No AI activity yet.");

        panel.add(toolbar, BorderLayout.NORTH);
        panel.add(new JScrollPane(table), BorderLayout.CENTER);
        panel.add(aiFeedUsage, BorderLayout.SOUTH);
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

    /** Template generation remains available; starting cloud target scans is disabled. */
    private JComponent buildPdcpScanPanel(ReconController controller) {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT));
        p.setBorder(BorderFactory.createTitledBorder("ProjectDiscovery cloud scans"));
        p.add(new JLabel("Cloud scan creation is paused until target requests can be governed."));
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
