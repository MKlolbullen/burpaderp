package com.victor.reconloop;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import javax.swing.*;
import java.net.URI;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static burp.api.montoya.http.handler.RequestToBeSentAction.continueWith;
import static burp.api.montoya.http.handler.ResponseReceivedAction.continueWith;
import static burp.api.montoya.http.message.HttpRequestResponse.httpRequestResponse;
import static burp.api.montoya.http.message.requests.HttpRequest.httpRequestFromUrl;
import static burp.api.montoya.scanner.audit.issues.AuditIssue.auditIssue;

final class ReconController implements HttpHandler {
    private final MontoyaApi api;
    private final RegexHound regexHound = new RegexHound();
    private final DiscoveryEngine discovery = new DiscoveryEngine();
    private final ParameterProfiler parameterProfiler = new ParameterProfiler();
    private final GfPatternLoader gfPatterns = new GfPatternLoader();
    private final PayloadLibrary payloadLibrary = new PayloadLibrary();
    private final ResponseSignalEngine responseSignals = new ResponseSignalEngine();
    private final XssReflectionEngine xssReflectionEngine = new XssReflectionEngine();
    private final CertificateTransparencyClient ctClient;
    private final ParameterDiscoveryEngine parameterDiscovery;
    private final ActiveTestEngine activeTestEngine;

    private final ReconModel.FindingTableModel findingModel;
    private final ReconModel.DiscoveryTableModel discoveryModel;
    private final ReconModel.ParameterTableModel parameterModel;
    private final ReconModel.ReflectionTableModel reflectionModel;
    private final ReconModel.ActiveTableModel activeModel;

    private final BlockingQueue<QueueItem> queue = new LinkedBlockingQueue<>();
    private final Set<String> queuedOrVisited = ConcurrentHashMap.newKeySet();
    private final Set<String> discoveredUrls = ConcurrentHashMap.newKeySet();
    private final Set<String> issueDedupe = ConcurrentHashMap.newKeySet();
    private final Set<String> parameterDedupe = ConcurrentHashMap.newKeySet();
    private final Set<String> reflectionDedupe = ConcurrentHashMap.newKeySet();
    private final Set<String> activeDedupe = ConcurrentHashMap.newKeySet();
    private final Set<String> oobDedupe = ConcurrentHashMap.newKeySet();
    private final Map<String, HttpRequest> originTemplates = new ConcurrentHashMap<>();

    private final ExecutorService worker = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "Burp-Recon-Hound");
        t.setDaemon(true);
        return t;
    });

    private final ExecutorService activeWorker = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "Burp-Recon-Hound-Active");
        t.setDaemon(true);
        return t;
    });

    private final ScheduledExecutorService oobPoller = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "Burp-Recon-Hound-Collaborator");
        t.setDaemon(true);
        return t;
    });

    private volatile CollaboratorClient collaborator;

    private final AtomicBoolean running = new AtomicBoolean(true);
    private final AtomicBoolean crawlEnabled = new AtomicBoolean(true);
    private final AtomicBoolean addToScope = new AtomicBoolean(true);
    private final AtomicBoolean sameOriginOnly = new AtomicBoolean(true);
    private final AtomicBoolean includeInfoFindings = new AtomicBoolean(false);
    private final AtomicBoolean scanGfPatterns = new AtomicBoolean(true);
    private final AtomicBoolean followRedirects = new AtomicBoolean(true);
    private final AtomicBoolean detectReflections = new AtomicBoolean(true);
    private final AtomicBoolean activeTestsEnabled = new AtomicBoolean(false);
    private final AtomicInteger maxRequests = new AtomicInteger(500);
    private final AtomicInteger maxRedirects = new AtomicInteger(8);
    private final AtomicInteger activeThrottleMillis = new AtomicInteger(150);
    private final AtomicInteger activeRequestBudget = new AtomicInteger(60);
    private final AtomicInteger sentRequests = new AtomicInteger(0);

    private volatile StatusListener statusListener = s -> {};

    ReconController(MontoyaApi api,
                    ReconModel.FindingTableModel findingModel,
                    ReconModel.DiscoveryTableModel discoveryModel,
                    ReconModel.ParameterTableModel parameterModel,
                    ReconModel.ReflectionTableModel reflectionModel,
                    ReconModel.ActiveTableModel activeModel) {
        this.api = api;
        this.findingModel = findingModel;
        this.discoveryModel = discoveryModel;
        this.parameterModel = parameterModel;
        this.reflectionModel = reflectionModel;
        this.activeModel = activeModel;
        this.ctClient = new CertificateTransparencyClient(api);
        this.parameterDiscovery = new ParameterDiscoveryEngine(api);
        this.activeTestEngine = new ActiveTestEngine(api, activeThrottleMillis.get());
        worker.submit(this::workerLoop);
        oobPoller.scheduleWithFixedDelay(this::pollCollaborator, 12, 12, TimeUnit.SECONDS);
    }

    interface StatusListener { void update(String status); }
    record QueueItem(URI uri, URI rootOrigin, String source) {}

    void setStatusListener(StatusListener listener) { this.statusListener = listener == null ? s -> {} : listener; }
    void setCrawlEnabled(boolean value) { crawlEnabled.set(value); }
    void setAddToScope(boolean value) { addToScope.set(value); }
    void setSameOriginOnly(boolean value) { sameOriginOnly.set(value); }
    void setIncludeInfoFindings(boolean value) { includeInfoFindings.set(value); }
    void setScanGfPatterns(boolean value) { scanGfPatterns.set(value); }
    void setFollowRedirects(boolean value) { followRedirects.set(value); }
    void setDetectReflections(boolean value) { detectReflections.set(value); }
    void setActiveTestsEnabled(boolean value) { activeTestsEnabled.set(value); }
    void setMaxRequests(int value) { maxRequests.set(Math.max(1, value)); }
    void setMaxRedirects(int value) { maxRedirects.set(Math.max(0, value)); }
    void setActiveRequestBudget(int value) { activeRequestBudget.set(Math.max(1, value)); }

    int gfPackCount() { return gfPatterns.packCount(); }
    int payloadCount() { return payloadLibrary.totalPayloads(); }
    String payloadCategories() { return String.join(", ", payloadLibrary.categories()); }
    int paramWordlistSize() { return parameterDiscovery.wordlistSize(); }

    /** Lazily creates the Collaborator client; returns false if Collaborator is unavailable. */
    private boolean ensureCollaborator() {
        if (collaborator != null) return true;
        try {
            collaborator = api.collaborator().createClient();
            activeTestEngine.setCollaborator(collaborator);
            api.logging().logToOutput("[Recon Hound] Collaborator client ready for OOB (SSRF / blind XSS) testing.");
            return true;
        } catch (Exception e) {
            api.logging().logToError("Collaborator unavailable; OOB tests disabled", e);
            return false;
        }
    }

    void enumerateSubdomains(String domain) {
        activeWorker.submit(() -> {
            String normalized = CertificateTransparencyClient.normalizeDomain(domain);
            if (normalized == null) {
                api.logging().logToError("Invalid domain for crt.sh: " + domain);
                return;
            }
            api.logging().logToOutput("[Recon Hound] crt.sh enumeration for " + normalized);
            Set<String> hosts = ctClient.enumerate(normalized);
            for (String host : hosts) {
                try {
                    URI uri = URI.create("https://" + host + "/");
                    addDiscovered(uri, uri, "crt.sh CT log", false);
                } catch (Exception ignored) {}
            }
            api.logging().logToOutput("[Recon Hound] crt.sh returned " + hosts.size() + " host(s) for " + normalized);
            publishStatus();
        });
    }

    void discoverParameters(String url) {
        activeWorker.submit(() -> {
            String target = url == null ? "" : url.trim();
            if (!target.startsWith("http")) { api.logging().logToError("Invalid parameter-discovery URL: " + target); return; }
            if (!api.scope().isInScope(target)) { api.logging().logToError("Target not in scope: " + target); return; }
            HttpRequest base = httpRequestFromUrl(target);
            api.logging().logToOutput("[Recon Hound] Arjun-style parameter discovery on " + target
                    + " (" + parameterDiscovery.wordlistSize() + " candidates)");
            for (ParameterDiscoveryEngine.Discovered found :
                    parameterDiscovery.discover(base, activeRequestBudget.get() * 3, activeThrottleMillis.get())) {
                addActiveRow("INFO", "PARAM", found.name(), "discovered", found.evidence(), found.url());
            }
            publishStatus();
        });
    }

    void runActiveTests() {
        if (!activeTestsEnabled.get()) {
            api.logging().logToOutput("[Recon Hound] Active tests are disabled; enable the opt-in checkbox first.");
            return;
        }
        ensureCollaborator();
        activeWorker.submit(() -> {
            List<HttpRequest> targets = api.siteMap().requestResponses().stream()
                    .map(HttpRequestResponse::request)
                    .filter(Objects::nonNull)
                    .filter(HttpRequest::isInScope)
                    .filter(HttpRequest::hasParameters)
                    .collect(java.util.stream.Collectors.toMap(HttpRequest::url, r -> r, (a, b) -> a, LinkedHashMap::new))
                    .values().stream().toList();

            api.logging().logToOutput("[Recon Hound] Active testing " + targets.size() + " in-scope parameterised request(s).");
            for (HttpRequest base : targets) {
                if (!activeTestsEnabled.get()) break;
                for (ActiveTestEngine.ActiveFinding finding : activeTestEngine.test(base, activeRequestBudget.get())) {
                    reportActiveFinding(finding, base);
                }
                publishStatus();
            }
            api.logging().logToOutput("[Recon Hound] Active testing pass complete. OOB results will arrive asynchronously.");
        });
    }

    void enqueueSeeds(String multiline) {
        if (multiline == null) return;
        for (String line : multiline.split("\\R")) {
            String value = line.trim();
            if (value.isEmpty() || value.startsWith("#")) continue;
            try {
                URI uri = URI.create(value);
                addDiscovered(uri, uri, "manual seed", true);
            } catch (IllegalArgumentException e) {
                api.logging().logToError("Invalid seed URL: " + value);
            }
        }
    }

    void queueCurrentInScopeSiteMap() {
        worker.submit(() -> {
            api.siteMap().requestResponses().stream()
                    .map(HttpRequestResponse::request)
                    .filter(Objects::nonNull)
                    .filter(HttpRequest::isInScope)
                    .forEach(req -> {
                        try {
                            URI uri = URI.create(req.url());
                            rememberTemplate(req);
                            profileParameters(req, "site-map");
                            addDiscovered(uri, uri, "site map", true);
                        } catch (Exception ignored) {}
                    });
            publishStatus();
        });
    }

    void pause() { crawlEnabled.set(false); publishStatus(); }
    void resume() { crawlEnabled.set(true); publishStatus(); }

    void reset() {
        queue.clear();
        queuedOrVisited.clear();
        discoveredUrls.clear();
        issueDedupe.clear();
        parameterDedupe.clear();
        reflectionDedupe.clear();
        activeDedupe.clear();
        sentRequests.set(0);
        SwingUtilities.invokeLater(() -> {
            findingModel.clear();
            discoveryModel.clear();
            parameterModel.clear();
            reflectionModel.clear();
            activeModel.clear();
        });
        publishStatus();
    }

    void shutdown() {
        running.set(false);
        worker.shutdownNow();
        activeWorker.shutdownNow();
        oobPoller.shutdownNow();
    }

    String status() {
        return "Running: " + crawlEnabled.get()
                + " | Queue: " + queue.size()
                + " | Seen: " + queuedOrVisited.size()
                + " | Discovered: " + discoveredUrls.size()
                + " | Sent: " + sentRequests.get() + "/" + maxRequests.get()
                + " | Findings: " + issueDedupe.size()
                + " | Reflections: " + reflectionDedupe.size()
                + " | Active: " + activeDedupe.size()
                + " | GF packs: " + gfPatterns.packCount()
                + " | Payloads: " + payloadLibrary.totalPayloads();
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
        try {
            if (request.isInScope()) {
                rememberTemplate(request);
                profileParameters(request, "request");
                scanMessage(request.toString(), "request", request.url(), null);
                discoverFrom(URI.create(request.url()), request.toString(), "request");
            }
        } catch (Exception e) {
            api.logging().logToError("Request processing failed", e);
        }
        return continueWith(request);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
        try {
            HttpRequest request = response.initiatingRequest();
            if (request != null && request.isInScope()) {
                rememberTemplate(request);
                profileParameters(request, "response-origin");
                HttpRequestResponse pair = httpRequestResponse(request, response);
                processResponsePair(pair, "response");
                api.siteMap().add(pair);
            }
        } catch (Exception e) {
            api.logging().logToError("Response processing failed", e);
        }
        return continueWith(response);
    }

    private void discoverFrom(URI base, String text, String sourceType) {
        for (URI uri : discovery.discover(base, text)) {
            addDiscovered(uri, base, sourceType + " " + base, false);
            for (URI dir : discovery.parentDirectories(uri)) {
                addDiscovered(dir, base, "parent directory of " + uri, false);
            }
        }
    }

    private void addDiscovered(URI candidate, URI source, String sourceLabel, boolean forceQueue) {
        if (candidate == null || candidate.getHost() == null) return;
        if (sameOriginOnly.get() && source != null && !DiscoveryEngine.sameOrigin(candidate, source)) return;

        String url = candidate.toString();
        boolean fresh = discoveredUrls.add(url);

        if (addToScope.get() && !api.scope().isInScope(url)) {
            api.scope().includeInScope(url);
        }

        if (fresh) {
            String kind = InterestingResourceCatalog.classify(candidate);
            SwingUtilities.invokeLater(() -> discoveryModel.add(new ReconModel.DiscoveryRow(kind, url, sourceLabel)));
        }

        boolean shouldQueue = forceQueue || InterestingResourceCatalog.interesting(candidate) || !candidate.getPath().endsWith("/");
        if (shouldQueue && (crawlEnabled.get() || forceQueue) && queuedOrVisited.add(url)) {
            queue.offer(new QueueItem(candidate, source == null ? candidate : source, sourceLabel));
        }
        publishStatus();
    }

    private void workerLoop() {
        while (running.get()) {
            try {
                QueueItem item = queue.poll(500, TimeUnit.MILLISECONDS);
                if (item == null) continue;
                while (running.get() && !crawlEnabled.get()) Thread.sleep(250);
                if (!running.get()) return;
                if (sentRequests.get() >= maxRequests.get()) {
                    queue.clear();
                    publishStatus();
                    continue;
                }
                if (!api.scope().isInScope(item.uri().toString())) continue;

                crawlOne(item);
                publishStatus();
                Thread.sleep(80);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            } catch (Exception e) {
                api.logging().logToError("Recon Hound request failed", e);
            }
        }
    }

    private void crawlOne(QueueItem item) {
        URI current = item.uri();
        Set<String> redirectSeen = new HashSet<>();
        int hop = 0;

        while (current != null && hop <= maxRedirects.get() && running.get()) {
            if (sentRequests.get() >= maxRequests.get()) return;
            if (!api.scope().isInScope(current.toString())) return;
            if (!redirectSeen.add(current.toString())) return;

            HttpRequest request = buildAuthenticatedGet(current);
            sentRequests.incrementAndGet();
            api.logging().logToOutput("[Recon Hound] GET " + current + (hop > 0 ? " [redirect hop " + hop + "]" : ""));

            HttpRequestResponse rr = api.http().sendRequest(request);
            if (rr == null || !rr.hasResponse() || rr.response() == null) return;

            api.siteMap().add(rr);
            processActivePair(rr, hop);

            HttpResponse response = rr.response();
            short code = response.statusCode();
            if (!followRedirects.get() || code < 300 || code >= 400) return;

            String location = response.headerValue("Location");
            URI next = discovery.redirectTarget(current, location);
            if (next == null) return;
            addDiscovered(next, item.rootOrigin(), "redirect " + code + " from " + current, false);
            current = next;
            hop++;
        }
    }

    private HttpRequest buildAuthenticatedGet(URI uri) {
        HttpRequest request = httpRequestFromUrl(uri.toString()).withMethod("GET");
        HttpRequest template = originTemplates.get(DiscoveryEngine.origin(uri));
        if (template == null) return request;

        for (String header : List.of("Cookie", "Authorization", "User-Agent", "Accept", "Accept-Language", "Referer", "X-Requested-With")) {
            String value = template.headerValue(header);
            if (value != null && !value.isBlank()) request = request.withHeader(header, value);
        }
        return request;
    }

    private void processActivePair(HttpRequestResponse rr, int redirectHop) {
        try {
            HttpRequest request = rr.request();
            if (request == null || !request.isInScope()) return;
            rememberTemplate(request);
            profileParameters(request, redirectHop > 0 ? "redirect-request" : "active-request");
            scanMessage(request.toString(), redirectHop > 0 ? "redirect-request" : "active-request", request.url(), rr);
            discoverFrom(URI.create(request.url()), request.toString(), "active request");
            processResponsePair(rr, redirectHop > 0 ? "redirect-response" : "active-response");
        } catch (Exception e) {
            api.logging().logToError("Active pair processing failed", e);
        }
    }

    private void processResponsePair(HttpRequestResponse pair, String location) {
        HttpRequest request = pair.request();
        HttpResponse response = pair.response();
        if (request == null || response == null) return;

        scanMessage(response.toString(), location, request.url(), pair);
        discoverFrom(URI.create(request.url()), response.toString(), location);

        for (ResponseSignalEngine.Signal signal : responseSignals.analyze(response)) {
            addSyntheticFinding(signal.severity(), "response", signal.name(), location, signal.value(), request.url());
            if (!"INFO".equals(signal.severity()) && !"LOW".equals(signal.severity())) {
                addSignalIssue(signal, location, request.url(), pair);
            }
        }

        if (detectReflections.get()) {
            analyzeReflections(request, response, pair);
        }

        short code = response.statusCode();
        if (code >= 300 && code < 400) {
            String target = response.headerValue("Location");
            URI next = discovery.redirectTarget(URI.create(request.url()), target);
            if (next != null) addDiscovered(next, URI.create(request.url()), "redirect " + code + " from " + request.url(), false);
        }
    }

    private void profileParameters(HttpRequest request, String location) {
        for (ParameterProfiler.Candidate candidate : parameterProfiler.profile(request)) {
            String classes = candidate.classes().isEmpty() ? "generic mutation" : String.join(", ", candidate.classes());
            String dedupe = request.url() + "\0" + candidate.type() + "\0" + candidate.name();
            if (!parameterDedupe.add(dedupe)) continue;
            SwingUtilities.invokeLater(() -> parameterModel.add(new ReconModel.ParameterRow(
                    candidate.score(), candidate.type(), candidate.name(), classes, candidate.valuePreview(), request.url()
            )));
        }
    }

    private void analyzeReflections(HttpRequest request, HttpResponse response, HttpRequestResponse pair) {
        for (XssReflectionEngine.Reflection reflection : xssReflectionEngine.analyze(request, response)) {
            String dedupe = "reflect\0" + reflection.url() + "\0" + reflection.parameter()
                    + "\0" + reflection.type() + "\0" + reflection.context();
            if (!reflectionDedupe.add(dedupe)) continue;

            String surviving = reflection.survivingChars().isEmpty() ? "(none literal)" : reflection.survivingChars();
            List<XssVectorLibrary.Vector> vectors = reflection.viableVectors();
            String suggestion = vectors.isEmpty()
                    ? "no viable vector for surviving chars"
                    : vectors.get(0).rendered();

            SwingUtilities.invokeLater(() -> reflectionModel.add(new ReconModel.ReflectionRow(
                    reflection.severity(), reflection.parameter(), reflection.type(),
                    reflection.context().label(), surviving, suggestion,
                    reflection.valuePreview(), reflection.url()
            )));

            if (pair != null && ("HIGH".equals(reflection.severity()) || "MEDIUM".equals(reflection.severity()))) {
                addReflectionIssue(reflection, vectors, pair);
            }
        }
        publishStatus();
    }

    private void addReflectionIssue(XssReflectionEngine.Reflection reflection,
                                    List<XssVectorLibrary.Vector> vectors,
                                    HttpRequestResponse pair) {
        AuditIssueSeverity severity = "HIGH".equals(reflection.severity())
                ? AuditIssueSeverity.HIGH : AuditIssueSeverity.MEDIUM;

        StringBuilder vectorHtml = new StringBuilder();
        for (XssVectorLibrary.Vector vector : vectors) {
            vectorHtml.append("<li><code>").append(escape(vector.rendered())).append("</code> &mdash; ")
                    .append(escape(vector.note())).append("</li>");
        }
        if (vectorHtml.isEmpty()) vectorHtml.append("<li>No pre-canned vector matches the surviving character set.</li>");

        String detail = "<b>Reflected input candidate for cross-site scripting</b><br>"
                + "Parameter: <code>" + escape(reflection.parameter()) + "</code> (" + escape(reflection.type()) + ")<br>"
                + "Reflection context: " + escape(reflection.context().label()) + "<br>"
                + "Characters surviving unencoded: <code>" + escape(reflection.survivingChars().isEmpty()
                        ? "(none literal)" : reflection.survivingChars()) + "</code><br>"
                + "Occurrences: " + reflection.occurrences() + "<br>"
                + "Reflected value: <code>" + escape(reflection.valuePreview()) + "</code><br><br>"
                + "Context-appropriate vectors from the XSS cheat sheet to validate manually:<ul>"
                + vectorHtml + "</ul>";

        AuditIssue issue = auditIssue(
                "Recon Hound: reflected parameter (" + reflection.context().label() + ")",
                detail,
                "HTML-encode reflected values for their output context, apply a strict Content-Security-Policy, "
                        + "and avoid reflecting attacker-controlled input into scripts or URL attributes.",
                reflection.url(), severity, AuditIssueConfidence.TENTATIVE,
                "Recon Hound passively maps parameter values that are reflected into responses and classifies the sink context.",
                "Reflection is necessary but not sufficient for XSS; confirm by injecting a context-appropriate vector against an authorised target.",
                severity, pair
        );
        api.siteMap().add(issue);
    }

    private void scanMessage(String text, String location, String url, HttpRequestResponse pair) {
        for (RegexHound.Finding finding : regexHound.scan(text, location, url, includeInfoFindings.get())) {
            String dedupe = "hound\0" + finding.rule().id() + "\0" + finding.value() + "\0" + url;
            if (!issueDedupe.add(dedupe)) continue;

            SwingUtilities.invokeLater(() -> findingModel.add(new ReconModel.FindingRow(
                    finding.rule().severity().name(), finding.rule().provider(), finding.rule().name(),
                    location, RegexHound.redact(finding.value()), url
            )));

            if (pair != null && finding.rule().severity() != RegexHound.Severity.INFO) addAuditIssue(finding, pair);
        }

        if (scanGfPatterns.get()) {
            for (GfPatternLoader.GfMatch match : gfPatterns.scan(text)) {
                String dedupe = "gf\0" + match.pack() + "\0" + match.value() + "\0" + url;
                if (!issueDedupe.add(dedupe)) continue;
                addSyntheticFinding("INFO", "gf", "gf:" + match.pack(), location, match.value(), url);
            }
        }
        publishStatus();
    }

    private void reportActiveFinding(ActiveTestEngine.ActiveFinding finding, HttpRequest base) {
        String status = finding.confirmed() ? "confirmed" : "pending OOB";
        String dedupe = "active\0" + finding.testClass() + "\0" + finding.parameter()
                + "\0" + finding.url() + "\0" + finding.evidence();
        if (!activeDedupe.add(dedupe)) return;

        addActiveRow(finding.severity(), finding.testClass(), finding.parameter(), status, finding.evidence(), finding.url());

        if (finding.confirmed() && !"INFO".equals(finding.severity())) {
            AuditIssueSeverity severity = switch (finding.severity()) {
                case "HIGH" -> AuditIssueSeverity.HIGH;
                case "MEDIUM" -> AuditIssueSeverity.MEDIUM;
                default -> AuditIssueSeverity.LOW;
            };
            String detail = "<b>Active test: " + escape(finding.testClass()) + "</b><br>"
                    + "Parameter: <code>" + escape(finding.parameter()) + "</code><br>"
                    + "Evidence: " + escape(finding.evidence());
            AuditIssue issue = auditIssue(
                    "Recon Hound: " + finding.testClass() + " (" + finding.parameter() + ")",
                    detail,
                    activeRemediation(finding.testClass()),
                    finding.url(), severity, AuditIssueConfidence.FIRM,
                    "Recon Hound actively probes parameters for SSRF, SSTI and XSS when active testing is enabled.",
                    "Confirm the impact manually and only test targets you are authorised to assess.",
                    severity);
            api.siteMap().add(issue);
        }
    }

    private void addActiveRow(String severity, String testClass, String parameter, String status, String evidence, String url) {
        SwingUtilities.invokeLater(() -> activeModel.add(new ReconModel.ActiveRow(
                severity, testClass, parameter, status, evidence, url)));
    }

    private static String activeRemediation(String testClass) {
        return switch (testClass) {
            case "SSRF", "SSRF-OOB" -> "Validate and allow-list outbound request destinations; block internal ranges and cloud metadata endpoints.";
            case "SSTI" -> "Never pass user input into template source; use logic-less templates or strict sandboxing.";
            case "XSS", "XSS-blind" -> "Context-encode reflected input and apply a strict Content-Security-Policy.";
            default -> "Validate and encode user input for its output/interpreter context.";
        };
    }

    private void pollCollaborator() {
        CollaboratorClient client = collaborator;
        if (client == null) return;
        try {
            for (Interaction interaction : client.getAllInteractions()) {
                String key = interaction.id().toString() + "\0" + interaction.type();
                if (!oobDedupe.add(key)) continue;

                String[] context = interaction.customData()
                        .map(ActiveTestEngine::decodeCorrelation)
                        .orElse(null);
                String testClass = context != null ? context[0] : "OOB";
                String parameter = context != null ? context[1] : "(unknown)";
                String url = context != null ? context[2] : "(unknown)";
                String evidence = interaction.type() + " interaction from "
                        + interaction.clientIp().getHostAddress();

                addActiveRow("HIGH", testClass + "-OOB", parameter, "OOB confirmed", evidence, url);

                AuditIssue issue = auditIssue(
                        "Recon Hound: out-of-band " + testClass + " interaction",
                        "<b>Confirmed OOB interaction</b><br>Class: " + escape(testClass) + "<br>"
                                + "Parameter: <code>" + escape(parameter) + "</code><br>"
                                + "Interaction: " + escape(evidence) + "<br>"
                                + "The Collaborator payload injected into this parameter triggered a "
                                + interaction.type() + " callback, confirming server-side request forgery "
                                + "or blind script execution.",
                        activeRemediation(testClass),
                        "(unknown)".equals(url) ? "https://" + interaction.clientIp().getHostAddress() : url,
                        AuditIssueSeverity.HIGH, AuditIssueConfidence.FIRM,
                        "Recon Hound correlates Burp Collaborator interactions back to the injected parameter.",
                        "OOB interactions are strong evidence; verify the affected functionality manually.",
                        AuditIssueSeverity.HIGH);
                api.siteMap().add(issue);
            }
            publishStatus();
        } catch (Exception e) {
            api.logging().logToError("Collaborator polling failed", e);
        }
    }

    private void addSignalIssue(ResponseSignalEngine.Signal signal, String location, String url, HttpRequestResponse pair) {
        if (pair == null) return;
        String dedupe = "signal-issue\0" + signal.name() + "\0" + signal.value() + "\0" + url;
        if (!issueDedupe.add(dedupe)) return;

        AuditIssueSeverity severity = switch (signal.severity()) {
            case "HIGH" -> AuditIssueSeverity.HIGH;
            case "MEDIUM" -> AuditIssueSeverity.MEDIUM;
            default -> AuditIssueSeverity.LOW;
        };

        String detail = "<b>Response signal: " + escape(signal.name()) + "</b><br>"
                + "Location: " + escape(location) + "<br>"
                + "Evidence: <code>" + escape(signal.value()) + "</code><br><br>"
                + "Recon Hound flags disclosure signals (stack traces, debug/error output, source-map "
                + "references, directory listings, internal-hostname hints) in in-scope responses.";

        AuditIssue issue = auditIssue(
                "Recon Hound: " + signal.name(),
                detail,
                "Suppress verbose errors and stack traces in production, remove source-map references from "
                        + "public assets, disable directory listing, and avoid leaking internal hostnames.",
                url, severity, AuditIssueConfidence.FIRM,
                "Recon Hound passively inspects in-scope responses for information-disclosure signals.",
                "Disclosure findings are heuristic; confirm the leaked content is sensitive before reporting.",
                severity, pair
        );
        api.siteMap().add(issue);
    }

    private void addSyntheticFinding(String severity, String provider, String rule, String location, String value, String url) {
        String dedupe = "synthetic\0" + provider + "\0" + rule + "\0" + value + "\0" + url;
        if (!issueDedupe.add(dedupe)) return;
        String safe = value == null ? "" : (value.length() > 220 ? value.substring(0, 217) + "..." : value);
        SwingUtilities.invokeLater(() -> findingModel.add(new ReconModel.FindingRow(
                severity, provider, rule, location, safe, url
        )));
    }

    private void addAuditIssue(RegexHound.Finding finding, HttpRequestResponse pair) {
        AuditIssueSeverity severity = switch (finding.rule().severity()) {
            case CRITICAL, HIGH -> AuditIssueSeverity.HIGH;
            case MEDIUM -> AuditIssueSeverity.MEDIUM;
            case LOW -> AuditIssueSeverity.LOW;
            case INFO -> AuditIssueSeverity.INFORMATION;
        };
        AuditIssueConfidence confidence = switch (finding.rule().confidence()) {
            case HIGH -> AuditIssueConfidence.CERTAIN;
            case MEDIUM -> AuditIssueConfidence.FIRM;
            case LOW -> AuditIssueConfidence.TENTATIVE;
        };

        String detail = "<b>Regex Hound match</b><br>"
                + "Provider: " + escape(finding.rule().provider()) + "<br>"
                + "Location: " + escape(finding.location()) + "<br>"
                + "Matched value: <code>" + escape(RegexHound.redact(finding.value())) + "</code><br>"
                + "Entropy: " + String.format(Locale.ROOT, "%.2f", finding.entropy()) + "<br><br>"
                + "Review the original request/response and validate whether the credential or token is live.";

        AuditIssue issue = auditIssue(
                "Recon Hound: " + finding.rule().name(),
                detail,
                "Remove exposed credentials from client-visible content, rotate affected secrets, and constrain their privileges.",
                finding.url(), severity, confidence,
                "Recon Hound identifies credential, token, key, and security-relevant patterns in in-scope HTTP traffic.",
                "Secret scanning is heuristic; verify context before remediation.",
                severity, pair
        );
        api.siteMap().add(issue);
    }

    private void rememberTemplate(HttpRequest request) {
        try {
            originTemplates.put(DiscoveryEngine.origin(URI.create(request.url())), request.copyToTempFile());
        } catch (Exception ignored) {}
    }

    private void publishStatus() {
        String value = status();
        SwingUtilities.invokeLater(() -> statusListener.update(value));
    }

    private static String escape(String value) {
        if (value == null) return "";
        return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }
}
