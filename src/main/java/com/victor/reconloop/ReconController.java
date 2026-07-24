package com.victor.reconloop;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.persistence.PersistedObject;
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

final class ReconController implements HttpHandler {
    private final MontoyaApi api;
    private final RegexHound regexHound = new RegexHound();
    private final DiscoveryEngine discovery = new DiscoveryEngine();
    private final ParameterProfiler parameterProfiler = new ParameterProfiler();
    private final GfPatternLoader gfPatterns = new GfPatternLoader();
    private final PayloadLibrary payloadLibrary = new PayloadLibrary();
    private final ResponseSignalEngine responseSignals = new ResponseSignalEngine();
    private final XssReflectionEngine xssReflectionEngine = new XssReflectionEngine();
    private final WebHygieneEngine webHygiene = new WebHygieneEngine();
    private final DependencyVulnEngine scaEngine = new DependencyVulnEngine();
    private final LlmClient llmClient = new LlmClient();
    private final CertificateTransparencyClient ctClient;
    private final ParameterDiscoveryEngine parameterDiscovery;
    private final ActiveTestEngine activeTestEngine;
    private final IssueReporter reporter;
    private final PdcpClient pdcp = new PdcpClient();
    private volatile PersistedObject store;

    private final ReconModel.FindingTableModel findingModel;
    private final ReconModel.DiscoveryTableModel discoveryModel;
    private final ReconModel.ParameterTableModel parameterModel;
    private final ReconModel.ReflectionTableModel reflectionModel;
    private final ReconModel.ActiveTableModel activeModel;
    private final ReconModel.AssetTableModel assetModel;

    private final BlockingQueue<QueueItem> queue = new LinkedBlockingQueue<>();
    private final Set<String> queuedOrVisited = ConcurrentHashMap.newKeySet();
    private final Set<String> discoveredUrls = ConcurrentHashMap.newKeySet();
    private final Set<String> issueDedupe = ConcurrentHashMap.newKeySet();
    private final Set<String> parameterDedupe = ConcurrentHashMap.newKeySet();
    private final Set<String> reflectionDedupe = ConcurrentHashMap.newKeySet();
    private final Set<String> activeDedupe = ConcurrentHashMap.newKeySet();
    private final Set<String> oobDedupe = ConcurrentHashMap.newKeySet();
    private final Set<String> minedMaps = ConcurrentHashMap.newKeySet();
    private final Set<String> minedWebpack = ConcurrentHashMap.newKeySet();
    private final Set<String> ingestedSpecs = ConcurrentHashMap.newKeySet();
    private final Set<String> llmJsAnalyzed = ConcurrentHashMap.newKeySet();
    private final Set<String> assetHosts = ConcurrentHashMap.newKeySet();
    private final Set<String> assetIps = ConcurrentHashMap.newKeySet();
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

    // Dedicated pool for LLM API calls only (never target-directed traffic), sized to the number of
    // providers so enabling all of them runs genuinely in parallel. Kept separate from activeWorker,
    // whose single-thread serialization deliberately paces requests fired at the target itself.
    private final ExecutorService llmWorker = Executors.newFixedThreadPool(LlmProvider.values().length, r -> {
        Thread t = new Thread(r, "Burp-Recon-Hound-LLM");
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
                    ReconModel.ActiveTableModel activeModel,
                    ReconModel.AssetTableModel assetModel) {
        this.api = api;
        this.reporter = new IssueReporter(api);
        this.findingModel = findingModel;
        this.discoveryModel = discoveryModel;
        this.parameterModel = parameterModel;
        this.reflectionModel = reflectionModel;
        this.activeModel = activeModel;
        this.assetModel = assetModel;
        this.ctClient = new CertificateTransparencyClient(api);
        this.parameterDiscovery = new ParameterDiscoveryEngine(api);
        this.activeTestEngine = new ActiveTestEngine(api, activeThrottleMillis.get());
        try {
            this.store = api.persistence().extensionData();
            restoreState();
        } catch (Exception e) {
            api.logging().logToError("Persisted-state restore skipped", e);
        }
        worker.submit(this::workerLoop);
        oobPoller.scheduleWithFixedDelay(this::pollCollaborator, 12, 12, TimeUnit.SECONDS);
        oobPoller.scheduleWithFixedDelay(this::saveState, 60, 60, TimeUnit.SECONDS);
    }

    /** Restores dedupe keys, asset inventory, and Findings/Hosts rows from the Burp project. */
    private void restoreState() {
        if (store == null) return;
        reporter.restore(PersistedState.loadStrings(store, PersistedState.K_FILED));
        assetHosts.addAll(PersistedState.loadStrings(store, PersistedState.K_HOSTS));
        assetIps.addAll(PersistedState.loadStrings(store, PersistedState.K_IPS));
        List<ReconModel.FindingRow> findings = PersistedState.loadFindings(store);
        List<ReconModel.AssetRow> assets = PersistedState.loadAssets(store);
        if (findings.isEmpty() && assets.isEmpty()) return;
        SwingUtilities.invokeLater(() -> {
            for (int i = findings.size() - 1; i >= 0; i--) findingModel.add(findings.get(i));
            for (int i = assets.size() - 1; i >= 0; i--) assetModel.add(assets.get(i));
        });
        api.logging().logToOutput("[Recon Hound] Restored " + findings.size() + " finding(s) and "
                + (assetHosts.size() + assetIps.size()) + " asset(s) from the Burp project.");
    }

    /** Persists current state to the Burp project (runs the model snapshot on the EDT). */
    private void saveState() {
        if (store == null) return;
        SwingUtilities.invokeLater(() -> {
            try {
                PersistedState.saveStrings(store, PersistedState.K_FILED, reporter.filedSnapshot());
                PersistedState.saveStrings(store, PersistedState.K_HOSTS, new ArrayList<>(assetHosts));
                PersistedState.saveStrings(store, PersistedState.K_IPS, new ArrayList<>(assetIps));
                PersistedState.saveFindings(store, findingModel.snapshot());
                PersistedState.saveAssets(store, assetModel.snapshot());
            } catch (Exception e) {
                api.logging().logToError("Persisted-state save failed", e);
            }
        });
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

    /** Adds every collected host and IP asset to Burp's target scope (both http and https). */
    int addAllAssetsToScope() {
        int count = 0;
        for (String host : assetHosts) {
            api.scope().includeInScope("https://" + host + "/");
            api.scope().includeInScope("http://" + host + "/");
            count++;
        }
        for (String ip : assetIps) {
            String literal = ip.contains(":") ? "[" + ip + "]" : ip;
            api.scope().includeInScope("https://" + literal + "/");
            api.scope().includeInScope("http://" + literal + "/");
            count++;
        }
        api.logging().logToOutput("[Recon Hound] Added " + count + " host/IP asset(s) to Burp scope.");
        publishStatus();
        return count;
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

    /**
     * Opt-in active JWT test: replays in-scope requests that carry a JWT with an {@code alg:none}
     * forgery (empty signature) and compares the response to the valid token's. If the forged token
     * is accepted, the server is not verifying signatures — a full authentication bypass. Only
     * GET/HEAD/OPTIONS requests are replayed to avoid side effects.
     */
    void runJwtAttacks() {
        if (!activeTestsEnabled.get()) {
            api.logging().logToOutput("[Recon Hound] Active tests are disabled; enable the opt-in checkbox first.");
            return;
        }
        activeWorker.submit(() -> {
            record JwtTarget(HttpRequest request, String token) {}
            List<JwtTarget> targets = new ArrayList<>();
            Set<String> seen = new HashSet<>();
            for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
                HttpRequest req = rr.request();
                if (req == null || !req.isInScope()) continue;
                if (!SAFE_METHODS.contains(req.method().toUpperCase(Locale.ROOT))) continue;
                for (String token : JwtAttackEngine.extractJwts(req)) {
                    if (seen.add(req.url() + "\0" + token)) targets.add(new JwtTarget(req, token));
                }
            }
            api.logging().logToOutput("[Recon Hound] JWT alg:none test on " + targets.size() + " JWT-bearing request(s).");

            int budget = activeRequestBudget.get();
            int sent = 0;
            for (JwtTarget target : targets) {
                if (!activeTestsEnabled.get() || sent >= budget) break;
                try {
                    HttpRequestResponse valid = api.http().sendRequest(target.request());
                    sent++;
                    if (valid == null || valid.response() == null) continue;
                    int validStatus = valid.response().statusCode();
                    if (validStatus >= 400) continue;   // token not granting access here; nothing to bypass
                    int validLen = valid.response().bodyToString().length();

                    boolean reported = false;
                    for (String forgedToken : JwtAttackEngine.forgeNoneVariants(target.token())) {
                        if (sent >= budget) break;
                        HttpRequest forgedReq = httpRequestFromString(target.request(),
                                target.request().toString().replace(target.token(), forgedToken));
                        HttpRequestResponse forged = api.http().sendRequest(forgedReq);
                        sent++;
                        Thread.sleep(activeThrottleMillis.get());
                        if (forged == null || forged.response() == null) continue;
                        int forgedStatus = forged.response().statusCode();
                        int forgedLen = forged.response().bodyToString().length();
                        boolean accepted = forgedStatus < 400 && forgedStatus == validStatus
                                && Math.abs(forgedLen - validLen) <= Math.max(64, validLen / 10);

                        addActiveRow(accepted ? "HIGH" : "INFO", "JWT-none", "alg=none",
                                accepted ? "accepted" : "rejected",
                                "valid=" + validStatus + "/" + validLen + " forged=" + forgedStatus + "/" + forgedLen,
                                target.request().url());

                        if (accepted && !reported) {
                            reported = true;
                            reporter.report("jwt-none\0" + target.request().url(),
                                    "JWT alg:none accepted (authentication bypass)",
                                    "<b>Server accepts an unsigned alg:none JWT</b><br>"
                                            + "URL: <code>" + escape(target.request().url()) + "</code><br><br>"
                                            + "A token re-encoded with <code>alg:none</code> and an empty signature was accepted "
                                            + "(status " + forgedStatus + ", matching the valid token's " + validStatus + "). "
                                            + "Signatures are not verified, so an attacker can forge arbitrary claims "
                                            + "(any user/role) — full authentication bypass.",
                                    "Reject <code>alg:none</code> server-side; pin the expected algorithm and always verify the signature.",
                                    target.request().url(), AuditIssueSeverity.HIGH, AuditIssueConfidence.FIRM,
                                    "Recon Hound replays JWT-bearing requests with an alg:none forgery to test signature validation.",
                                    "Confirm the forged token grants privileged access before reporting.",
                                    forged);
                        }
                    }

                    // Weak-secret forgery: if the HMAC secret is a known weak value, mint a tampered token
                    // signed with it and confirm the server accepts a token it never issued.
                    String alg = JwtAttackEngine.headerAlg(target.token());
                    String[] parts = target.token().split("\\.");
                    if (alg != null && alg.startsWith("hs") && parts.length >= 3 && sent < budget) {
                        String secret = WebHygieneEngine.crackHmac(parts[0] + "." + parts[1], parts[2], alg);
                        String forgedToken = secret == null ? null : JwtAttackEngine.forgeWithSecret(target.token(), secret, alg);
                        if (forgedToken != null) {
                            HttpRequest forgedReq = httpRequestFromString(target.request(),
                                    target.request().toString().replace(target.token(), forgedToken));
                            HttpRequestResponse forged = api.http().sendRequest(forgedReq);
                            sent++;
                            Thread.sleep(activeThrottleMillis.get());
                            if (forged != null && forged.response() != null) {
                                int forgedStatus = forged.response().statusCode();
                                boolean accepted = forgedStatus < 400 && forgedStatus == validStatus;
                                addActiveRow(accepted ? "HIGH" : "INFO", "JWT-forge", "weak-secret",
                                        accepted ? "accepted" : "rejected",
                                        "secret=\"" + secret + "\" status=" + forgedStatus, target.request().url());
                                if (accepted) {
                                    reporter.report("jwt-forge\0" + target.request().url(),
                                            "JWT weak-secret forgery confirmed (authentication bypass)",
                                            "<b>Server accepts a token forged with a cracked secret</b><br>"
                                                    + "URL: <code>" + escape(target.request().url()) + "</code><br><br>"
                                                    + "The token's HMAC secret is the well-known value \"" + escape(secret) + "\". "
                                                    + "A token re-signed with it (and a tampered claim) was accepted (status "
                                                    + forgedStatus + "). An attacker can mint tokens with arbitrary claims "
                                                    + "(any user/role) — full authentication bypass / privilege escalation.",
                                            "Rotate to a long, random signing key; never use guessable or boilerplate secrets.",
                                            target.request().url(), AuditIssueSeverity.HIGH, AuditIssueConfidence.CERTAIN,
                                            "Recon Hound cracks the HMAC secret offline, then replays a token re-signed with it to confirm forgery.",
                                            "This is a confirmed authentication bypass; validate scope before exploiting.",
                                            forged);
                                }
                            }
                        }
                    }
                    publishStatus();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                } catch (Exception e) {
                    api.logging().logToError("JWT attack failed for " + target.request().url(), e);
                }
            }
            api.logging().logToOutput("[Recon Hound] JWT alg:none test complete (" + sent + " request(s)).");
            publishStatus();
        });
    }

    /**
     * Opt-in subdomain-takeover check: fetches each enumerated host and matches known
     * "unclaimed resource" fingerprints (GitHub Pages, S3, Heroku, …). A match suggests a dangling
     * DNS record whose backend could be claimed by an attacker. Authorised targets only.
     */
    void runSubdomainTakeoverCheck() {
        if (!activeTestsEnabled.get()) {
            api.logging().logToOutput("[Recon Hound] Active tests are disabled; enable the opt-in checkbox first.");
            return;
        }
        activeWorker.submit(() -> {
            List<String> hosts = new ArrayList<>(assetHosts);
            api.logging().logToOutput("[Recon Hound] Subdomain-takeover check on " + hosts.size() + " enumerated host(s).");
            int budget = activeRequestBudget.get() * 2;
            int sent = 0;
            for (String host : hosts) {
                if (!activeTestsEnabled.get() || sent >= budget) break;
                for (String scheme : List.of("https://", "http://")) {
                    if (sent >= budget) break;
                    try {
                        HttpRequestResponse rr = api.http().sendRequest(httpRequestFromUrl(scheme + host + "/"));
                        sent++;
                        Thread.sleep(activeThrottleMillis.get());
                        if (rr == null || rr.response() == null) continue;
                        String service = SubdomainTakeoverEngine.match(rr.response().bodyToString());
                        if (service == null) continue;

                        String url = scheme + host + "/";
                        addActiveRow("HIGH", "Takeover", host, "fingerprint", service, url);
                        reporter.report("takeover\0" + host + "\0" + service,
                                "Potential subdomain takeover (" + service + ")",
                                "<b>Dangling " + escape(service) + " resource</b><br>"
                                        + "Host: <code>" + escape(host) + "</code><br><br>"
                                        + "The host serves " + escape(service) + "'s 'unclaimed resource' page, which suggests a "
                                        + "dangling DNS record whose backend no longer exists. An attacker who claims that backend "
                                        + "can serve arbitrary content on this subdomain (phishing, cookie/session theft, CSP bypass).",
                                "Remove the dangling DNS record, or (re)claim the " + escape(service) + " resource it points to.",
                                url, AuditIssueSeverity.HIGH, AuditIssueConfidence.TENTATIVE,
                                "Recon Hound fetches enumerated hosts and matches known subdomain-takeover fingerprints.",
                                "Confirm the DNS points to a genuinely unclaimed resource before attempting a takeover (authorised only).",
                                rr);
                        break;   // one scheme is enough for this host
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        return;
                    } catch (Exception e) {
                        api.logging().logToError("Takeover check failed for " + host, e);
                    }
                }
            }
            api.logging().logToOutput("[Recon Hound] Subdomain-takeover check complete (" + sent + " request(s)).");
            publishStatus();
        });
    }

    private static HttpRequest httpRequestFromString(HttpRequest template, String raw) {
        return HttpRequest.httpRequest(template.httpService(), raw);
    }

    private static final Set<String> SAFE_METHODS = Set.of("GET", "HEAD", "OPTIONS");

    void runAccessControlTest(String sessionHeaders, boolean unauthenticated) {
        AccessControlEngine engine = new AccessControlEngine(sessionHeaders, unauthenticated);
        if (!engine.configured()) {
            api.logging().logToError("Access-control test needs alternate session headers or the unauthenticated option.");
            return;
        }
        activeWorker.submit(() -> {
            List<HttpRequestResponse> targets = api.siteMap().requestResponses().stream()
                    .filter(rr -> rr.request() != null && rr.hasResponse() && rr.response() != null)
                    .filter(rr -> rr.request().isInScope())
                    .filter(rr -> SAFE_METHODS.contains(rr.request().method().toUpperCase(Locale.ROOT)))
                    .collect(java.util.stream.Collectors.toMap(
                            rr -> rr.request().method() + " " + rr.request().url(),
                            rr -> rr, (a, b) -> a, LinkedHashMap::new))
                    .values().stream().toList();

            api.logging().logToOutput("[Recon Hound] Access-control replay of " + targets.size()
                    + " safe (GET/HEAD/OPTIONS) in-scope request(s) under the alternate identity.");

            for (HttpRequestResponse original : targets) {
                try {
                    HttpRequest replayRequest = engine.applyIdentity(original.request());
                    if (!api.scope().isInScope(replayRequest.url())) continue;
                    HttpRequestResponse replay = api.http().sendRequest(replayRequest);
                    if (replay == null || replay.response() == null) continue;

                    int origLen = original.response().bodyToString().length();
                    int replayLen = replay.response().bodyToString().length();
                    AccessControlEngine.Result result = AccessControlEngine.classify(
                            original.response().statusCode(), origLen,
                            replay.response().statusCode(), replayLen);

                    String url = original.request().url();
                    String dedupe = "ac\0" + url + "\0" + result.verdict();
                    if (!activeDedupe.add(dedupe)) continue;

                    addActiveRow(result.severity(), "AccessControl", original.request().method(),
                            result.verdict().name().toLowerCase(Locale.ROOT), result.detail(), url);

                    if (result.verdict() == AccessControlEngine.Verdict.BYPASSED
                            || result.verdict() == AccessControlEngine.Verdict.PARTIAL) {
                        AuditIssueSeverity severity = result.verdict() == AccessControlEngine.Verdict.BYPASSED
                                ? AuditIssueSeverity.HIGH : AuditIssueSeverity.MEDIUM;
                        reporter.report(
                                "ac-issue\0" + url + "\0" + result.verdict(),
                                "broken access control (" + result.verdict().name().toLowerCase(Locale.ROOT) + ")",
                                "<b>Access-control replay</b><br>" + escape(result.detail())
                                        + "<br>Identity: " + (unauthenticated ? "unauthenticated" : "alternate session"),
                                "Enforce authorization server-side on every request; do not rely on the UI hiding functionality.",
                                url, severity,
                                result.verdict() == AccessControlEngine.Verdict.BYPASSED
                                        ? AuditIssueConfidence.FIRM : AuditIssueConfidence.TENTATIVE,
                                "Recon Hound replays privileged requests under a lower-privileged identity and compares responses.",
                                "Confirm the exposed data/action is genuinely sensitive; response size alone can mislead.",
                                replay);
                    }
                    publishStatus();
                } catch (Exception e) {
                    api.logging().logToError("Access-control replay failed", e);
                }
            }
            api.logging().logToOutput("[Recon Hound] Access-control test complete.");
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
        oobDedupe.clear();
        reporter.clearFiled();   // else the site map never re-files after the tables are cleared
        minedMaps.clear();
        minedWebpack.clear();
        ingestedSpecs.clear();
        llmJsAnalyzed.clear();
        assetHosts.clear();
        assetIps.clear();
        sentRequests.set(0);
        SwingUtilities.invokeLater(() -> {
            findingModel.clear();
            discoveryModel.clear();
            parameterModel.clear();
            reflectionModel.clear();
            activeModel.clear();
            assetModel.clear();
        });
        saveState();
        publishStatus();
    }

    void shutdown() {
        running.set(false);
        // Stop the periodic saver first so it can't race the final blocking save on the PersistedObject.
        oobPoller.shutdownNow();
        saveStateBlocking();
        worker.shutdownNow();
        activeWorker.shutdownNow();
        llmWorker.shutdownNow();
    }

    /** Synchronous save for extension unload, when the async EDT task might not run in time. */
    private void saveStateBlocking() {
        if (store == null) return;
        try {
            java.util.concurrent.atomic.AtomicReference<List<ReconModel.FindingRow>> findings = new java.util.concurrent.atomic.AtomicReference<>(List.of());
            java.util.concurrent.atomic.AtomicReference<List<ReconModel.AssetRow>> assets = new java.util.concurrent.atomic.AtomicReference<>(List.of());
            Runnable snapshot = () -> { findings.set(findingModel.snapshot()); assets.set(assetModel.snapshot()); };
            if (SwingUtilities.isEventDispatchThread()) snapshot.run();
            else SwingUtilities.invokeAndWait(snapshot);
            PersistedState.saveStrings(store, PersistedState.K_FILED, reporter.filedSnapshot());
            PersistedState.saveStrings(store, PersistedState.K_HOSTS, new ArrayList<>(assetHosts));
            PersistedState.saveStrings(store, PersistedState.K_IPS, new ArrayList<>(assetIps));
            PersistedState.saveFindings(store, findings.get());
            PersistedState.saveAssets(store, assets.get());
        } catch (Exception e) {
            api.logging().logToError("Persisted-state save on shutdown failed", e);
        }
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
                + " | Assets: " + (assetHosts.size() + assetIps.size())
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
        recordAsset(candidate.getHost(), sourceLabel);
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
        URI requestUri = safeUri(request.url());
        if (requestUri != null) discoverFrom(requestUri, response.toString(), location);

        for (ResponseSignalEngine.Signal signal : responseSignals.analyze(response)) {
            addSyntheticFinding(signal.severity(), "response", signal.name(), location, signal.value(), request.url());
            addSignalIssue(signal, location, request.url(), pair);
        }

        if (detectReflections.get()) {
            analyzeReflections(request, response, pair);
        }

        analyzeHygiene(request, response, pair);
        mineSourceMap(request.url(), response, pair);
        mineWebpackChunks(request.url(), response);
        scanDependencies(request.url(), response, pair);
        scanDomXss(request.url(), response, pair);
        ingestApiSpec(request.url(), response, pair);

        short code = response.statusCode();
        if (code >= 300 && code < 400 && requestUri != null) {
            String target = response.headerValue("Location");
            URI next = discovery.redirectTarget(requestUri, target);
            if (next != null) addDiscovered(next, requestUri, "redirect " + code + " from " + request.url(), false);
        }
    }

    /** Parses a URL string, returning null instead of throwing on malformed input. */
    private static URI safeUri(String url) {
        try {
            return URI.create(url);
        } catch (Exception e) {
            return null;
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

    private void analyzeHygiene(HttpRequest request, HttpResponse response, HttpRequestResponse pair) {
        for (WebHygieneEngine.Note note : webHygiene.analyze(request, response)) {
            String url = request == null ? "" : request.url();
            String dedupe = "hygiene\0" + note.name() + "\0" + url;
            if (!issueDedupe.add(dedupe)) continue;
            SwingUtilities.invokeLater(() -> findingModel.add(new ReconModel.FindingRow(
                    note.severity(), "hygiene", note.name(), "response", note.detail(), url)));
            addToSiteMap(buildHygieneIssue(note, url, pair));
        }
    }

    private AuditIssue buildHygieneIssue(WebHygieneEngine.Note note, String url, HttpRequestResponse pair) {
        return reporter.buildIfNew(
                "hygiene-issue\0" + note.name() + "\0" + url,
                note.name(),
                "<b>" + escape(note.name()) + "</b><br>" + escape(note.detail()),
                "Review the affected security header / token handling and harden per OWASP guidance.",
                url, IssueReporter.severity(note.severity()), AuditIssueConfidence.FIRM,
                "Recon Hound passively inspects CORS, CSP and JWT hygiene in in-scope responses.",
                "Header-based findings are heuristic; confirm exploitability in context.",
                pair);
    }

    private void mineSourceMap(String url, HttpResponse response, HttpRequestResponse pair) {
        try {
            String contentType = response.headerValue("Content-Type");
            String body = response.bodyToString();
            if (!SourceMapMiner.looksLikeSourceMap(url, contentType, body)) return;
            if (!minedMaps.add(url)) return;

            List<SourceMapMiner.Source> sources = SourceMapMiner.parse(body);
            if (sources.isEmpty()) return;
            api.logging().logToOutput("[Recon Hound] Reconstructed " + sources.size() + " source(s) from " + url);
            for (SourceMapMiner.Source source : sources) {
                String label = "source-map:" + source.name();
                scanMessage(source.content(), label, url, pair);
                try {
                    discoverFrom(URI.create(url), source.content(), label);
                } catch (Exception ignored) {}
            }
            addSyntheticFinding("INFO", "sourcemap", "Source map exposed", "response",
                    sources.size() + " original source file(s) recoverable", url);
            reporter.report("sourcemap-issue\0" + url,
                    "source map exposed",
                    "<b>JavaScript source map is publicly exposed</b><br>"
                            + "URL: <code>" + escape(url) + "</code><br>"
                            + "Recovered original source files: " + sources.size() + "<br><br>"
                            + "Exposed source maps reveal original (pre-minification) source, including comments, "
                            + "internal paths, endpoints and sometimes secrets. Recon Hound re-scanned the recovered "
                            + "sources for endpoints and credentials.",
                    "Remove <code>.map</code> files (or their <code>//# sourceMappingURL</code> references) from "
                            + "production, or restrict access to them.",
                    url, AuditIssueSeverity.INFORMATION, AuditIssueConfidence.CERTAIN,
                    "Recon Hound reconstructs original sources from exposed source maps and mines them for endpoints/secrets.",
                    "Impact depends on what the recovered source reveals; review the reconstructed files.",
                    pair);
        } catch (Exception e) {
            api.logging().logToError("Source-map mining failed for " + url, e);
        }
    }

    private void mineWebpackChunks(String url, HttpResponse response) {
        try {
            if (!isJavaScriptResponse(url, response)) return;
            if (!minedWebpack.add(url)) return;
            String body = response.bodyToString();
            if (!WebpackMiner.looksLikeWebpack(body)) return;
            URI base = URI.create(url);
            Set<URI> chunks = WebpackMiner.reconstruct(base, body);
            if (chunks.isEmpty()) return;
            for (URI chunk : chunks) addDiscovered(chunk, base, "webpack chunk from " + url, false);
            api.logging().logToOutput("[Recon Hound] Reconstructed " + chunks.size() + " webpack chunk URL(s) from " + url);
            addSyntheticFinding("INFO", "webpack", "Webpack chunks reconstructed", "response",
                    chunks.size() + " lazy-loaded chunk URL(s) queued from the bundle", url);
        } catch (Exception e) {
            api.logging().logToError("Webpack mining failed for " + url, e);
        }
    }

    private void scanDependencies(String url, HttpResponse response, HttpRequestResponse pair) {
        try {
            String contentType = response.headerValue("Content-Type");
            boolean html = contentType != null && contentType.toLowerCase(Locale.ROOT).contains("html");
            if (!isJavaScriptResponse(url, response) && !html) return;
            for (AuditIssue issue : scaIssues(url, response.bodyToString(), pair)) addToSiteMap(issue);
        } catch (Exception e) {
            api.logging().logToError("Dependency (SCA) scan failed for " + url, e);
        }
    }

    private void scanDomXss(String url, HttpResponse response, HttpRequestResponse pair) {
        try {
            String contentType = response.headerValue("Content-Type");
            boolean html = contentType != null && contentType.toLowerCase(Locale.ROOT).contains("html");
            if (!isJavaScriptResponse(url, response) && !html) return;
            for (AuditIssue issue : domXssIssues(url, response.bodyToString(), pair)) addToSiteMap(issue);
        } catch (Exception e) {
            api.logging().logToError("DOM-XSS scan failed for " + url, e);
        }
    }

    /** Builds DOM-XSS issues; adds a UI row only when a finding is newly built. */
    private List<AuditIssue> domXssIssues(String url, String body, HttpRequestResponse pair) {
        List<AuditIssue> out = new ArrayList<>();
        int bodyOffset = (pair != null && pair.hasResponse()) ? pair.response().bodyOffset() : 0;
        for (DomXssEngine.DomFinding finding : DomXssEngine.analyze(body)) {
            int start = bodyOffset + finding.start();
            int end = bodyOffset + finding.end();
            String located = (pair != null && pair.hasResponse())
                    ? locatedEvidence(pair.response().toString(), start, end, false) : "";
            HttpRequestResponse evidence = IssueReporter.withResponseEvidence(pair, start, end);
            AuditIssue issue = reporter.buildIfNew(
                    "domxss\0" + url + "\0" + finding.sink() + "\0" + finding.source(),
                    "potential DOM XSS (" + finding.source() + " -> " + finding.sink() + ")",
                    "<b>Potential DOM-based XSS: a tainted source flows to a dangerous sink</b><br>"
                            + "Source: <code>" + escape(finding.source()) + "</code><br>"
                            + "Sink: <code>" + escape(finding.sink()) + "</code><br>"
                            + "Statement: <code>" + escape(finding.snippet()) + "</code>" + located + "<br><br>"
                            + "A user-controllable value reaches an HTML/script sink in the same statement. If it is not "
                            + "sanitised/encoded, an attacker can execute script in the victim's browser.",
                    "Encode/sanitise the value for its sink (use textContent instead of innerHTML, DOMPurify for HTML) "
                            + "and never pass untrusted input to eval/Function/document.write.",
                    url, AuditIssueSeverity.MEDIUM, AuditIssueConfidence.TENTATIVE,
                    "Recon Hound flags JS statements where a known DOM XSS source co-occurs with a dangerous sink.",
                    "Heuristic co-occurrence, not proven dataflow; confirm the source actually reaches the sink.",
                    evidence);
            if (issue != null) {
                addActiveRow("MEDIUM", "DOM-XSS", finding.sink(), "source->sink",
                        finding.source() + " -> " + finding.sink(), url);
                out.add(issue);
            }
        }
        return out;
    }

    /** Builds SCA issues for a response body; adds a UI row only when a finding is newly built. */
    private List<AuditIssue> scaIssues(String url, String body, HttpRequestResponse pair) {
        List<AuditIssue> out = new ArrayList<>();
        for (DependencyVulnEngine.LibIssue lib : scaEngine.scan(url, body)) {
            AuditIssue issue = reporter.buildIfNew(
                    "sca\0" + lib.library() + "\0" + lib.version() + "\0" + url,
                    "vulnerable dependency: " + lib.library() + " " + lib.version(),
                    "<b>Known-vulnerable JavaScript library</b><br>"
                            + "Library: <code>" + escape(lib.library()) + " " + escape(lib.version()) + "</code><br>"
                            + "Advisory: " + escape(lib.reference()) + "<br><br>" + escape(lib.detail()),
                    "Upgrade " + escape(lib.library()) + " to a fixed version, or replace it with a maintained alternative.",
                    url, IssueReporter.severity(lib.severity()), AuditIssueConfidence.TENTATIVE,
                    "Recon Hound matches client-side libraries against a curated database of known-vulnerable versions.",
                    "Version detection in minified bundles is heuristic; confirm the library and version.",
                    pair);
            if (issue != null) {
                addActiveRow(lib.severity(), "SCA", lib.library() + " " + lib.version(), "vulnerable", lib.reference(), url);
                out.add(issue);
            }
        }
        return out;
    }

    private static boolean isJavaScriptResponse(String url, HttpResponse response) {
        try {
            String contentType = response.headerValue("Content-Type");
            if (contentType != null && contentType.toLowerCase(Locale.ROOT).contains("javascript")) return true;
            String path = url.toLowerCase(Locale.ROOT);
            int q = path.indexOf('?');
            if (q >= 0) path = path.substring(0, q);
            return path.endsWith(".js") || path.endsWith(".mjs");
        } catch (Exception e) {
            return false;
        }
    }

    private void ingestApiSpec(String url, HttpResponse response, HttpRequestResponse pair) {
        try {
            String body = response.bodyToString();
            if (ApiSurfaceEngine.looksLikeGraphQlEndpoint(url)) {
                if (issueDedupe.add("graphql-endpoint\0" + url)) {
                    addSyntheticFinding("INFO", "graphql", "GraphQL endpoint", "response",
                            "GraphQL endpoint observed; use 'Introspect GraphQL' to map the schema", url);
                    reporter.report("graphql-endpoint-issue\0" + url,
                            "GraphQL endpoint exposed",
                            "<b>GraphQL endpoint observed</b><br>URL: <code>" + escape(url) + "</code><br><br>"
                                    + "GraphQL endpoints broaden attack surface (introspection, batching/aliasing abuse, "
                                    + "injection through resolvers). Use 'Introspect GraphQL' to map the schema.",
                            "Disable introspection in production, enforce authorization per field/resolver, and rate-limit queries.",
                            url, AuditIssueSeverity.INFORMATION, AuditIssueConfidence.FIRM,
                            "Recon Hound flags GraphQL endpoints discovered in in-scope traffic.",
                            "Endpoint exposure is informational; assess introspection and authorization separately.",
                            pair);
                }
            }
            if (!ApiSurfaceEngine.looksLikeOpenApi(body)) return;
            if (!ingestedSpecs.add(url)) return;

            URI base = URI.create(url);
            Set<String> paths = ApiSurfaceEngine.extractOpenApiPaths(body, base);
            for (String path : paths) {
                try {
                    URI uri = URI.create(path);
                    addDiscovered(uri, base, "OpenAPI spec " + url, false);
                } catch (Exception ignored) {}
            }
            api.logging().logToOutput("[Recon Hound] Ingested OpenAPI spec " + url + " (" + paths.size() + " path(s))");
            addSyntheticFinding("INFO", "openapi", "OpenAPI/Swagger spec", "response",
                    paths.size() + " documented endpoint(s) imported", url);
            reporter.report("openapi-issue\0" + url,
                    "OpenAPI/Swagger specification exposed",
                    "<b>OpenAPI/Swagger specification is publicly accessible</b><br>"
                            + "URL: <code>" + escape(url) + "</code><br>"
                            + "Documented endpoints imported: " + paths.size() + "<br><br>"
                            + "A public API spec enumerates endpoints, parameters and schemas, giving an attacker a "
                            + "complete map of the API surface. Recon Hound imported the documented paths into the crawl.",
                    "Restrict access to API specifications in production, or ensure every documented endpoint enforces "
                            + "authentication and authorization.",
                    url, AuditIssueSeverity.INFORMATION, AuditIssueConfidence.CERTAIN,
                    "Recon Hound ingests exposed OpenAPI/Swagger specs and expands them into the crawl surface.",
                    "Spec exposure is informational; the risk is the endpoints it reveals.",
                    pair);
        } catch (Exception e) {
            api.logging().logToError("API spec ingestion failed for " + url, e);
        }
    }

    /** On-demand, manual LLM analysis. Runs off the EDT against the already-resolved credential. */
    void analyzeWithLlm(LlmClient.LlmCredential credential, String system, String input,
                        java.util.function.Consumer<String> onResult) {
        llmWorker.submit(() -> {
            String result;
            try {
                result = llmClient.complete(credential.provider(), credential.model(), credential.apiKey(), system, input);
            } catch (Exception e) {
                result = "[error] " + e.getMessage();
            }
            String finalResult = result;
            SwingUtilities.invokeLater(() -> onResult.accept(finalResult));
        });
    }

    /**
     * On-demand, budget-capped LLM review of every in-scope JavaScript response in the site map.
     * Each parsed finding (bug + PoC + optional exploit chain) is filed as a native Burp audit issue
     * via {@link IssueReporter} and mirrored to the Active-tests table. Runs off the EDT; JS files
     * already analysed in a previous run are skipped, and no more than {@code maxFiles} fresh files
     * are sent per run (any remainder is reported, never silently dropped).
     *
     * <p>Files are round-robined across every enabled {@code credentials} entry and analysed
     * concurrently on {@link #llmWorker} — enabling more providers scales throughput, since each
     * provider's rate limit is independent.
     */
    void analyzeInScopeJavaScriptWithLlm(List<LlmClient.LlmCredential> credentials,
                                         int maxFiles, java.util.function.Consumer<String> onDone) {
        activeWorker.submit(() -> {
            if (credentials == null || credentials.isEmpty()) {
                SwingUtilities.invokeLater(() -> onDone.accept(
                        "[error] No LLM provider enabled — check a provider's box and set its key."));
                return;
            }

            List<HttpRequestResponse> jsPairs = api.siteMap().requestResponses().stream()
                    .filter(rr -> rr.request() != null && rr.hasResponse() && rr.response() != null)
                    .filter(rr -> rr.request().isInScope())
                    .filter(this::looksLikeJavaScript)
                    .collect(java.util.stream.Collectors.toMap(
                            rr -> rr.request().url(), rr -> rr, (a, b) -> a, LinkedHashMap::new))
                    .values().stream().toList();

            int totalInScope = jsPairs.size();
            List<HttpRequestResponse> fresh = jsPairs.stream()
                    .filter(rr -> !llmJsAnalyzed.contains(rr.request().url()))
                    .toList();
            List<HttpRequestResponse> toAnalyze = fresh.size() <= maxFiles ? fresh : fresh.subList(0, maxFiles);
            int skippedBudget = fresh.size() - toAnalyze.size();

            api.logging().logToOutput("[Recon Hound][LLM] JS analysis: " + totalInScope + " in-scope JS file(s), "
                    + toAnalyze.size() + " to analyse across " + credentials.size() + " provider(s), budget "
                    + maxFiles + " per run.");

            AtomicInteger findings = new AtomicInteger();
            AtomicInteger errors = new AtomicInteger();
            CountDownLatch latch = new CountDownLatch(toAnalyze.size());

            for (int i = 0; i < toAnalyze.size(); i++) {
                HttpRequestResponse rr = toAnalyze.get(i);
                LlmClient.LlmCredential credential = credentials.get(i % credentials.size());
                llmWorker.submit(() -> {
                    try {
                        String url = rr.request().url();
                        String body = rr.response().bodyToString();
                        api.logging().logToOutput("[Recon Hound][LLM] " + credential.provider().label()
                                + ": reviewing " + url + " (" + body.length() + " chars)");
                        LlmClient.LlmAnalysis analysis = llmClient.analyzeJavaScript(
                                credential.provider(), credential.model(), credential.apiKey(), url, body);

                        boolean transportError = analysis.findings().isEmpty() && analysis.error() != null
                                && (analysis.error().startsWith("[error]") || analysis.error().startsWith("[HTTP"));
                        if (transportError) {
                            // Don't record the URL as analysed — a transient 429/timeout must be retryable next run.
                            errors.incrementAndGet();
                            api.logging().logToOutput("[Recon Hound][LLM] " + url + ": " + firstLine(analysis.error()));
                        } else {
                            llmJsAnalyzed.add(url);
                            for (LlmClient.LlmFinding finding : analysis.findings()) {
                                findings.incrementAndGet();
                                fileLlmFinding(finding, url, rr);
                            }
                        }
                        publishStatus();
                    } catch (Exception e) {
                        errors.incrementAndGet();
                        api.logging().logToError("LLM JS analysis task failed", e);
                    } finally {
                        latch.countDown();
                    }
                });
            }

            try {
                latch.await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }

            int fAnalyzed = toAnalyze.size(), fFindings = findings.get(), fSkipped = skippedBudget,
                    fErrors = errors.get(), fTotal = totalInScope;
            StringBuilder summary = new StringBuilder();
            summary.append("LLM JS analysis complete: ").append(fAnalyzed).append(" file(s) analysed across ")
                    .append(credentials.size()).append(" provider(s), ")
                    .append(fFindings).append(" finding(s) filed as native Burp issues");
            if (fErrors > 0) summary.append(", ").append(fErrors).append(" file(s) errored");
            if (fSkipped > 0) {
                summary.append(". ").append(fSkipped).append(" file(s) left over the ").append(maxFiles)
                        .append("-file budget (of ").append(fTotal)
                        .append(" in-scope JS) — raise the budget and run again to continue.");
            } else {
                summary.append(". All ").append(fTotal).append(" in-scope JS file(s) covered.");
            }
            api.logging().logToOutput("[Recon Hound] " + summary);
            SwingUtilities.invokeLater(() -> onDone.accept(summary.toString()));
        });
    }

    /** Distinct in-scope target hosts (as https URLs) for a cloud scan, from collected assets + the site map. */
    List<String> collectInScopeTargets() {
        java.util.LinkedHashSet<String> hosts = new java.util.LinkedHashSet<>(assetHosts);
        api.siteMap().requestResponses().stream()
                .map(HttpRequestResponse::request)
                .filter(Objects::nonNull)
                .filter(HttpRequest::isInScope)
                .forEach(r -> {
                    try {
                        String host = URI.create(r.url()).getHost();
                        if (host != null) hosts.add(host.toLowerCase(Locale.ROOT));
                    } catch (Exception ignored) {}
                });
        List<String> out = new ArrayList<>();
        for (String host : hosts) out.add(host.startsWith("http") ? host : "https://" + host);
        return out;
    }

    /**
     * Runs a ProjectDiscovery Cloud (PDCP) Nuclei scan against {@code targets}, polls to completion, and
     * files each returned match as a native Burp audit issue via {@link IssueReporter}. Progress strings
     * are delivered on the EDT via {@code onProgress}. The key resolves from the UI field or $PDCP_API_KEY.
     */
    void runPdcpScan(String uiKey, String teamId, List<String> targets, List<String> templates,
                     boolean recommended, java.util.function.Consumer<String> onProgress) {
        java.util.function.Consumer<String> ui = s -> SwingUtilities.invokeLater(() -> onProgress.accept(s));
        activeWorker.submit(() -> {
            String key = (uiKey != null && !uiKey.isBlank()) ? uiKey.trim() : System.getenv("PDCP_API_KEY");
            if (key == null || key.isBlank()) {
                ui.accept("[error] No PDCP API key. Enter it above or export $PDCP_API_KEY.");
                return;
            }
            if (targets == null || targets.isEmpty()) {
                ui.accept("[error] No targets. Add hosts (one per line) or click 'Fill from in-scope'.");
                return;
            }
            boolean useRecommended = recommended || templates == null || templates.isEmpty();
            ui.accept("Creating PDCP scan for " + targets.size() + " target(s)"
                    + (useRecommended ? " (recommended templates)" : " (" + templates.size() + " template group(s))") + "...");

            PdcpClient.ScanCreated created = pdcp.createScan(key, teamId, "Recon Hound scan", targets,
                    templates == null ? List.of() : templates, useRecommended);
            if (created.scanId() == null) {
                ui.accept("Scan creation failed: " + created.error());
                return;
            }
            String scanId = created.scanId();
            api.logging().logToOutput("[Recon Hound][PDCP] scan " + scanId + " created for " + targets.size() + " target(s).");

            String status = "";
            for (int i = 0; i < 90 && running.get(); i++) {   // up to ~15 min at 10s cadence
                PdcpClient.ScanStatus st = pdcp.getScan(key, teamId, scanId);
                if (st.error() != null) { ui.accept("Status check: " + st.error()); }
                status = st.status() == null ? "" : st.status();
                ui.accept("Scan " + scanId + " — status: " + (status.isBlank() ? "?" : status)
                        + ", results so far: " + st.totalResult()
                        + (st.progress() > 0 ? ", progress: " + Math.round(st.progress()) + "%" : ""));
                if (isTerminalStatus(status)) break;
                try {
                    Thread.sleep(10_000);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                }
            }

            List<PdcpClient.Result> results = pdcp.getResults(key, teamId, targets, scanId, 500);
            int filed = 0;
            for (PdcpClient.Result result : results) {
                if (filePdcpResult(result)) filed++;
            }
            String summary = "PDCP scan " + scanId + " finished (status: " + (status.isBlank() ? "?" : status) + "). "
                    + results.size() + " result(s) returned, " + filed + " filed as native Burp issues"
                    + (filed < results.size() ? " (" + (results.size() - filed) + " duplicate/empty)" : "") + ".";
            api.logging().logToOutput("[Recon Hound] " + summary);
            ui.accept(summary);
            publishStatus();
        });
    }

    private static boolean isTerminalStatus(String status) {
        String s = status == null ? "" : status.toLowerCase(Locale.ROOT);
        return s.contains("done") || s.contains("finish") || s.contains("complete")
                || s.contains("fail") || s.contains("error") || s.contains("stop") || s.contains("cancel");
    }

    private boolean filePdcpResult(PdcpClient.Result r) {
        String url = r.target();
        if (url.isBlank()) return false;

        HttpRequestResponse pair = null;
        try {
            if (!r.request().isBlank() && !r.response().isBlank() && url.startsWith("http")) {
                HttpService service = HttpService.httpService(url);
                HttpRequest request = HttpRequest.httpRequest(service, r.request());
                HttpResponse response = HttpResponse.httpResponse(r.response());
                pair = httpRequestResponse(request, response);
            }
        } catch (Exception ignored) {
            // fall back to a text-only issue if the raw request/response won't parse
        }

        String detail = "<b>Nuclei match (ProjectDiscovery cloud): " + escape(r.name()) + "</b><br>"
                + "Template: <code>" + escape(r.templateId()) + "</code><br>"
                + "Target: <code>" + escape(url) + "</code><br>"
                + "Severity: " + escape(r.severity()) + "<br>"
                + (r.vulnId().isBlank() ? "" : "PDCP vuln id: <code>" + escape(r.vulnId()) + "</code><br>")
                + (r.vulnStatus().isBlank() ? "" : "PDCP status: " + escape(r.vulnStatus()) + "<br>")
                + "<br>Reported by a ProjectDiscovery cloud Nuclei scan launched from Recon Hound.";

        addActiveRow(r.severity().toUpperCase(Locale.ROOT), "Nuclei",
                r.templateId().isBlank() ? r.name() : r.templateId(),
                r.matched() ? "matched" : "reported", r.name(), url);

        return reporter.report(
                "pdcp\0" + r.templateId() + "\0" + url + "\0" + r.vulnId(),
                "Nuclei: " + (r.name().isBlank() ? r.templateId() : r.name()),
                detail,
                "Review the matched Nuclei template and remediate the underlying issue it detects.",
                url, IssueReporter.severity(r.severity()), AuditIssueConfidence.FIRM,
                "Recon Hound launched a ProjectDiscovery cloud Nuclei scan and imported matches as native Burp issues.",
                "Nuclei matches are generally reliable, but confirm exploitability in context.",
                pair);
    }

    /** On-demand: turns a natural-language description into a Nuclei YAML template via the LLM. */
    void generateNucleiTemplate(LlmClient.LlmCredential credential, String description,
                                java.util.function.Consumer<String> onResult) {
        llmWorker.submit(() -> {
            String result;
            try {
                result = llmClient.generateNucleiTemplate(credential.provider(), credential.model(), credential.apiKey(), description);
            } catch (Exception e) {
                result = "[error] " + e.getMessage();
            }
            String finalResult = result;
            SwingUtilities.invokeLater(() -> onResult.accept(finalResult));
        });
    }

    private boolean looksLikeJavaScript(HttpRequestResponse rr) {
        try {
            String url = rr.request().url().toLowerCase(Locale.ROOT);
            int q = url.indexOf('?');
            String path = q >= 0 ? url.substring(0, q) : url;
            if (path.endsWith(".js") || path.endsWith(".mjs") || path.endsWith(".jsx") || path.endsWith(".ts")) return true;
            String contentType = rr.response().headerValue("Content-Type");
            return contentType != null && contentType.toLowerCase(Locale.ROOT).contains("javascript");
        } catch (Exception e) {
            return false;
        }
    }

    private void fileLlmFinding(LlmClient.LlmFinding finding, String url, HttpRequestResponse pair) {
        String detail = "<b>LLM-identified issue: " + escape(finding.title()) + "</b><br>"
                + (finding.vulnClass().isBlank() ? "" : "Class: " + escape(finding.vulnClass()) + "<br>")
                + "Source: <code>" + escape(url) + "</code><br><br>"
                + (finding.description().isBlank() ? "" : "<b>Description</b><br>" + escape(finding.description()) + "<br><br>")
                + (finding.evidence().isBlank() ? "" : "<b>Evidence</b><br><code>" + escape(finding.evidence()) + "</code><br><br>")
                + (finding.poc().isBlank() ? "" : "<b>Proof of concept</b><br><code>" + escape(finding.poc()) + "</code><br><br>")
                + (finding.chain().isBlank() ? "" : "<b>Exploit chain (higher impact)</b><br>" + escape(finding.chain()) + "<br><br>")
                + "<i>Generated by an LLM from client-side source. Verify the PoC against an authorised target "
                + "before reporting — LLM output can be wrong or fabricated.</i>";
        String remediation = finding.remediation().isBlank()
                ? "Validate and encode untrusted input at the identified sink; review the cited code path."
                : finding.remediation();

        addActiveRow(finding.severity(), "LLM-JS",
                finding.vulnClass().isBlank() ? finding.title() : finding.vulnClass(),
                "reported", firstLine(finding.description().isBlank() ? finding.title() : finding.description()), url);

        reporter.report(
                "llm-js\0" + url + "\0" + finding.title(),
                "LLM: " + finding.title(),
                detail, remediation, url,
                IssueReporter.severity(finding.severity()), IssueReporter.confidence(finding.confidence()),
                "Recon Hound sent in-scope JavaScript to a user-configured LLM for on-demand vulnerability review.",
                "LLM output can be inaccurate or fabricated; confirm the PoC before relying on this finding.",
                pair);
    }

    private static String firstLine(String value) {
        if (value == null) return "";
        String line = value.strip();
        int nl = line.indexOf('\n');
        if (nl >= 0) line = line.substring(0, nl);
        return line.length() > 200 ? line.substring(0, 197) + "..." : line;
    }

    /**
     * On-demand: correlates the whole in-scope finding inventory (every audit issue on the site map)
     * into ranked exploit chains via the LLM, and files each chain as its own native Burp issue with a
     * bug-bounty-ready writeup. Runs off the EDT. The key resolves from the UI field or the provider $ENV.
     */
    void analyzeFindingChainsWithLlm(LlmClient.LlmCredential credential, int maxFindings,
                                     java.util.function.Consumer<String> onDone) {
        java.util.function.Consumer<String> ui = s -> SwingUtilities.invokeLater(() -> onDone.accept(s));
        llmWorker.submit(() -> {
            if (credential == null) { ui.accept("[error] No LLM provider enabled — check a provider's box and set its key."); return; }

            List<AuditIssue> issues = api.siteMap().issues().stream()
                    .filter(Objects::nonNull)
                    .filter(i -> { try { return api.scope().isInScope(i.baseUrl()); } catch (Exception e) { return false; } })
                    .filter(i -> !i.name().startsWith("Recon Hound: Chain:"))   // don't feed chains back in
                    .collect(java.util.stream.Collectors.toMap(
                            i -> i.name() + "\0" + i.baseUrl(), i -> i, (a, b) -> a, LinkedHashMap::new))
                    .values().stream()
                    .sorted(java.util.Comparator.comparingInt(ReconController::severityRank))
                    .limit(Math.max(1, maxFindings))
                    .toList();

            if (issues.isEmpty()) {
                ui.accept("[no in-scope findings to chain — run a crawl/scan first]");
                return;
            }

            StringBuilder inv = new StringBuilder("FINDINGS INVENTORY (" + issues.size() + "):\n");
            int n = 1;
            for (AuditIssue i : issues) {
                inv.append(n++).append(". [").append(i.severity()).append("] ").append(i.name())
                        .append(" — ").append(i.baseUrl()).append("\n");
                String d = htmlToText(i.detail());
                if (!d.isBlank()) inv.append("   ").append(d.length() > 300 ? d.substring(0, 297) + "..." : d).append("\n");
            }

            ui.accept("Analyzing " + issues.size() + " finding(s) for exploit chains with " + credential.provider().label() + "...");
            LlmClient.ChainAnalysis analysis = llmClient.analyzeChains(
                    credential.provider(), credential.model(), credential.apiKey(), inv.toString());
            if (analysis.chains().isEmpty()) {
                ui.accept(analysis.error() != null && analysis.error().startsWith("[error")
                        ? "Chaining failed: " + firstLine(analysis.error())
                        : "No exploit chains identified across " + issues.size() + " finding(s).");
                return;
            }
            int filed = 0;
            for (LlmClient.LlmChain chain : analysis.chains()) {
                if (fileChainIssue(chain, issues)) filed++;
            }
            String summary = "Chaining complete: " + filed + " exploit chain(s) filed as native Burp issues from "
                    + issues.size() + " finding(s). See Burp Issues / the Active tab.";
            api.logging().logToOutput("[Recon Hound] " + summary);
            ui.accept(summary);
            publishStatus();
        });
    }

    private static int severityRank(AuditIssue issue) {
        return switch (issue.severity()) {
            case HIGH -> 0;
            case MEDIUM -> 1;
            case LOW -> 2;
            case INFORMATION -> 3;
            default -> 4;
        };
    }

    /**
     * On-demand LLM false-positive triage of the Findings table. Reviews up to {@code maxFindings}
     * not-yet-triaged rows, sending the SAME numbered batch prompt to every enabled credential
     * concurrently; with more than one provider enabled, each finding's verdict is a majority vote
     * across providers rather than a single model's opinion. Verdicts are written into the Findings
     * table's "AI Triage" column in place (matched by finding content, not row index, since new
     * findings can be prepended while the LLM call is in flight) — {@link AuditIssue} itself is
     * immutable once filed, so nothing here can or does retouch the original native Burp issue.
     */
    void triageFindings(List<LlmClient.LlmCredential> credentials, int maxFindings,
                        java.util.function.Consumer<String> onDone) {
        java.util.function.Consumer<String> ui = s -> SwingUtilities.invokeLater(() -> onDone.accept(s));
        if (credentials == null || credentials.isEmpty()) {
            ui.accept("[error] No LLM provider enabled — check a provider's box and set its key.");
            return;
        }
        llmWorker.submit(() -> {
            java.util.concurrent.atomic.AtomicReference<List<ReconModel.FindingRow>> untriagedRef =
                    new java.util.concurrent.atomic.AtomicReference<>();
            Runnable snapshot = () -> untriagedRef.set(findingModel.untriagedSnapshot());
            try {
                if (SwingUtilities.isEventDispatchThread()) snapshot.run();
                else SwingUtilities.invokeAndWait(snapshot);
            } catch (Exception e) {
                ui.accept("[error] Could not read the Findings table: " + e.getMessage());
                return;
            }
            List<ReconModel.FindingRow> untriaged = untriagedRef.get();
            if (untriaged == null || untriaged.isEmpty()) {
                ui.accept("Nothing to triage — every current finding already has an AI Triage verdict.");
                return;
            }
            List<ReconModel.FindingRow> batch = untriaged.size() <= maxFindings ? untriaged : untriaged.subList(0, maxFindings);
            int leftover = untriaged.size() - batch.size();

            StringBuilder prompt = new StringBuilder("FINDINGS BATCH (" + batch.size() + "):\n");
            for (int i = 0; i < batch.size(); i++) {
                ReconModel.FindingRow r = batch.get(i);
                prompt.append(i + 1).append(". [").append(r.severity()).append("] ").append(r.provider())
                        .append(" / ").append(r.rule()).append(" @ ").append(r.location()).append("\n")
                        .append("   URL: ").append(r.url()).append("\n")
                        .append("   Evidence: ").append(truncate(r.value(), 300)).append("\n");
            }
            String batchPrompt = prompt.toString();

            ui.accept("Triaging " + batch.size() + " finding(s) across " + credentials.size() + " provider(s)...");

            List<LlmClient.TriageBatchResult> results = Collections.synchronizedList(new ArrayList<>());
            CountDownLatch latch = new CountDownLatch(credentials.size());
            for (LlmClient.LlmCredential credential : credentials) {
                llmWorker.submit(() -> {
                    try {
                        results.add(llmClient.triage(credential, batchPrompt));
                    } catch (Exception e) {
                        results.add(new LlmClient.TriageBatchResult(List.of(), "[error] " + e.getMessage()));
                    } finally {
                        latch.countDown();
                    }
                });
            }
            try {
                latch.await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }

            int erroredProviders = 0;
            Map<Integer, List<String>> votes = new HashMap<>();
            for (LlmClient.TriageBatchResult result : results) {
                if (result.verdicts().isEmpty()) { erroredProviders++; continue; }
                for (LlmClient.TriageVerdict v : result.verdicts()) {
                    votes.computeIfAbsent(v.index(), k -> new ArrayList<>()).add(normalizeVerdict(v.verdict()));
                }
            }

            Map<String, String> verdictsByKey = new HashMap<>();
            int fp = 0, tp = 0, uncertain = 0;
            for (int i = 0; i < batch.size(); i++) {
                String consensus = consensusVerdict(votes.get(i + 1));
                if (consensus.startsWith("LIKELY_FP")) fp++;
                else if (consensus.startsWith("LIKELY_TP")) tp++;
                else uncertain++;
                verdictsByKey.put(ReconModel.FindingTableModel.correlationKey(batch.get(i)), consensus);
            }

            SwingUtilities.invokeLater(() -> findingModel.applyTriage(verdictsByKey));

            int ftp = tp, ffp = fp, funcertain = uncertain, fLeftover = leftover, fErrored = erroredProviders;
            StringBuilder summary = new StringBuilder("Triage complete: ").append(batch.size())
                    .append(" finding(s) reviewed across ").append(credentials.size()).append(" provider(s) — ")
                    .append(ftp).append(" likely true positive, ").append(ffp).append(" likely false positive, ")
                    .append(funcertain).append(" uncertain.");
            if (fErrored > 0) summary.append(" (").append(fErrored).append(" provider(s) failed to respond.)");
            if (fLeftover > 0) {
                summary.append(" ").append(fLeftover).append(" finding(s) left over the ").append(maxFindings)
                        .append("-batch — run again to continue.");
            }

            if (ffp > 0 || ftp > 0) {
                reporter.report(
                        "triage-summary\0" + System.currentTimeMillis(),
                        "LLM triage summary",
                        "<b>LLM false-positive triage results</b><br>"
                                + "Reviewed: " + batch.size() + " finding(s) across " + credentials.size() + " provider(s)<br>"
                                + "Likely true positive: " + ftp + "<br>"
                                + "Likely false positive: " + ffp + "<br>"
                                + "Uncertain: " + funcertain + "<br><br>"
                                + "See the \"AI Triage\" column in the Findings tab for the per-finding verdict.",
                        "Review findings marked likely false positive before spending time on them; confirm likely-true-positive findings manually.",
                        "https://recon-hound.local/triage-summary",
                        AuditIssueSeverity.INFORMATION, AuditIssueConfidence.TENTATIVE,
                        "Recon Hound optionally sends filed findings to one or more configured LLMs to triage false-positive likelihood.",
                        "LLM triage is itself heuristic and can be wrong in either direction; it is an efficiency aid, not a substitute for manual review.");
            }
            api.logging().logToOutput("[Recon Hound] " + summary);
            ui.accept(summary.toString());
        });
    }

    private static String normalizeVerdict(String v) {
        if (v == null) return "UNCERTAIN";
        String upper = v.trim().toUpperCase(Locale.ROOT);
        if (upper.contains("FP") || upper.contains("FALSE")) return "LIKELY_FP";
        if (upper.contains("TP") || upper.contains("TRUE")) return "LIKELY_TP";
        return "UNCERTAIN";
    }

    /** Majority vote across every provider that answered for one finding; ties/no-answer fall back to UNCERTAIN. */
    private static String consensusVerdict(List<String> providerVotes) {
        if (providerVotes == null || providerVotes.isEmpty()) return "UNCERTAIN (no provider responded)";
        int fp = 0, tp = 0, uncertain = 0;
        for (String v : providerVotes) {
            switch (v) {
                case "LIKELY_FP" -> fp++;
                case "LIKELY_TP" -> tp++;
                default -> uncertain++;
            }
        }
        String label = (fp > tp && fp > uncertain) ? "LIKELY_FP"
                : (tp > fp && tp > uncertain) ? "LIKELY_TP"
                : "UNCERTAIN";
        return providerVotes.size() > 1 ? label + " (tp:" + tp + " fp:" + fp + " unc:" + uncertain + ")" : label;
    }

    private static String truncate(String value, int max) {
        if (value == null) return "";
        return value.length() <= max ? value : value.substring(0, max - 3) + "...";
    }

    private boolean fileChainIssue(LlmClient.LlmChain chain, List<AuditIssue> issues) {
        String url = firstUrl(chain.involvedUrls());
        if (url == null) url = issues.isEmpty() ? "https://chained.local/" : issues.get(0).baseUrl();
        String detail = "<b>Exploit chain: " + escape(chain.title()) + "</b><br>"
                + (chain.impact().isBlank() ? "" : "Impact: " + escape(chain.impact()) + "<br>")
                + "<br>"
                + (chain.writeup().isBlank() ? "" : "<b>Writeup</b><br>" + escape(chain.writeup()) + "<br><br>")
                + (chain.primitives().isBlank() ? "" : "<b>Primitives combined</b><br>" + escape(chain.primitives()) + "<br><br>")
                + (chain.steps().isBlank() ? "" : "<b>Steps</b><br><code>" + escape(chain.steps()).replace("\n", "<br>") + "</code><br><br>")
                + (chain.involvedUrls().isBlank() ? "" : "Involved URLs: " + escape(chain.involvedUrls()) + "<br><br>")
                + "<i>Proposed by an LLM from the finding inventory. Confirm each step against an authorised target before reporting.</i>";

        addActiveRow(chain.severity().toUpperCase(Locale.ROOT), "LLM-CHAIN", chain.title(), "proposed",
                firstLine(chain.impact().isBlank() ? chain.title() : chain.impact()), url);

        return reporter.report(
                "chain\0" + chain.title(),
                "Chain: " + chain.title(),
                detail,
                "Break the chain by remediating any one primitive; prioritise the highest-impact link.",
                url, IssueReporter.severity(chain.severity()), IssueReporter.confidence(chain.confidence()),
                "Recon Hound asked an LLM to correlate the finding inventory into higher-impact exploit chains.",
                "LLM-proposed chains can be wrong; validate each step before relying on it.");
    }

    private static String firstUrl(String urls) {
        if (urls == null) return null;
        for (String token : urls.split("[,\\s]+")) {
            String t = token.trim();
            if (t.startsWith("http://") || t.startsWith("https://")) return t;
        }
        return null;
    }

    private static String htmlToText(String html) {
        if (html == null) return "";
        return html.replaceAll("<[^>]+>", " ")
                .replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&amp;", "&")
                .replaceAll("\\s+", " ").strip();
    }

    void introspectGraphql(String url) {
        activeWorker.submit(() -> {
            String target = url == null ? "" : url.trim();
            if (!target.startsWith("http")) { api.logging().logToError("Invalid GraphQL URL: " + target); return; }
            if (!api.scope().isInScope(target)) { api.logging().logToError("GraphQL target not in scope: " + target); return; }
            try {
                HttpRequest request = httpRequestFromUrl(target)
                        .withMethod("POST")
                        .withUpdatedHeader("Content-Type", "application/json")
                        .withBody(ApiSurfaceEngine.introspectionQuery());
                HttpRequestResponse rr = api.http().sendRequest(request);
                if (rr == null || rr.response() == null) return;
                String summary = ApiSurfaceEngine.summarizeIntrospection(rr.response().bodyToString());
                boolean enabled = summary.contains("ENABLED");
                addActiveRow(enabled ? "MEDIUM" : "INFO", "GraphQL", "introspection",
                        enabled ? "confirmed" : "checked", summary, target);
                if (enabled && rr.hasResponse()) {
                    reporter.report(
                            "graphql-introspection-issue\0" + target,
                            "GraphQL introspection enabled",
                            "<b>GraphQL introspection is enabled</b><br>" + escape(summary),
                            "Disable introspection in production to reduce schema disclosure.",
                            target, AuditIssueSeverity.LOW, AuditIssueConfidence.FIRM,
                            "Recon Hound queried the GraphQL introspection endpoint on request.",
                            "Introspection disclosure is informational to low severity depending on exposure.",
                            rr);
                }
                api.logging().logToOutput("[Recon Hound] GraphQL introspection on " + target + ": " + summary);
            } catch (Exception e) {
                api.logging().logToError("GraphQL introspection failed for " + target, e);
            }
        });
    }

    /** Active GraphQL fuzzing beyond introspection: field-suggestion leakage, alias amplification, batching. */
    void fuzzGraphql(String url) {
        activeWorker.submit(() -> {
            String target = url == null ? "" : url.trim();
            if (!target.startsWith("http")) { api.logging().logToError("Invalid GraphQL URL: " + target); return; }
            if (!api.scope().isInScope(target)) { api.logging().logToError("GraphQL target not in scope: " + target); return; }
            try {
                HttpRequestResponse suggest = gqlPost(target, GraphQlFuzzEngine.suggestionQuery());
                if (bodyOf(suggest) != null && GraphQlFuzzEngine.hasFieldSuggestions(bodyOf(suggest))) {
                    addActiveRow("LOW", "GraphQL", "field-suggestions", "enabled", "'Did you mean' leaks schema", target);
                    reporter.report("gql-suggest\0" + target, "GraphQL field suggestions enabled",
                            "<b>GraphQL field suggestions are enabled</b><br>Even with introspection disabled, the server "
                                    + "returns 'Did you mean' hints for invalid fields, leaking schema details that help an attacker map the API.",
                            "Disable did-you-mean/field suggestions in production.",
                            target, AuditIssueSeverity.LOW, AuditIssueConfidence.FIRM,
                            "Recon Hound probes GraphQL with an invalid field to detect suggestion leakage.",
                            "Schema disclosure via suggestions is low severity but aids further attacks.", suggest);
                }

                int aliases = 100;
                HttpRequestResponse alias = gqlPost(target, GraphQlFuzzEngine.aliasQuery(aliases));
                if (bodyOf(alias) != null && GraphQlFuzzEngine.aliasingProcessed(bodyOf(alias), aliases)) {
                    addActiveRow("MEDIUM", "GraphQL", "alias-amplification", "enabled", aliases + " aliases in one request", target);
                    reporter.report("gql-alias\0" + target, "GraphQL alias-based amplification",
                            "<b>GraphQL processes many field aliases per request</b><br>" + aliases + " aliases of a field were "
                                    + "processed in a single request. Aliasing amplifies work/attempts (brute-forcing a login mutation, "
                                    + "resource exhaustion) while sending one request, bypassing per-request rate limits.",
                            "Enforce query cost/complexity limits and cap aliases per request.",
                            target, AuditIssueSeverity.MEDIUM, AuditIssueConfidence.FIRM,
                            "Recon Hound sends an alias-amplified query to test cost controls.",
                            "Confirm the amplification is usable against a sensitive operation.", alias);
                }

                HttpRequestResponse batch = gqlPost(target, GraphQlFuzzEngine.batchQuery());
                if (bodyOf(batch) != null && GraphQlFuzzEngine.batchingProcessed(bodyOf(batch))) {
                    addActiveRow("MEDIUM", "GraphQL", "query-batching", "enabled", "array of operations processed", target);
                    reporter.report("gql-batch\0" + target, "GraphQL query batching enabled",
                            "<b>GraphQL query batching is enabled</b><br>The endpoint processed a JSON array of operations in a "
                                    + "single request. Batching enables rate-limit bypass and brute force by packing many operations per request.",
                            "Disable array-based query batching, or apply per-operation rate limiting and cost analysis.",
                            target, AuditIssueSeverity.MEDIUM, AuditIssueConfidence.FIRM,
                            "Recon Hound sends a batched operation array to test whether batching is enabled.",
                            "Confirm batching is usable against a sensitive operation.", batch);
                }
                api.logging().logToOutput("[Recon Hound] GraphQL fuzzing complete for " + target);
            } catch (Exception e) {
                api.logging().logToError("GraphQL fuzzing failed for " + target, e);
            }
            publishStatus();
        });
    }

    private HttpRequestResponse gqlPost(String url, String jsonBody) {
        HttpRequest request = httpRequestFromUrl(url)
                .withMethod("POST")
                .withUpdatedHeader("Content-Type", "application/json")
                .withBody(jsonBody);
        return api.http().sendRequest(request);
    }

    private static String bodyOf(HttpRequestResponse rr) {
        return rr != null && rr.response() != null ? rr.response().bodyToString() : null;
    }

    /** Recon Hound's own audit issues on the site map (for report export). */
    List<AuditIssue> reconIssues() {
        List<AuditIssue> out = new ArrayList<>();
        for (AuditIssue issue : api.siteMap().issues()) {
            if (issue != null && issue.name() != null && issue.name().startsWith("Recon Hound")) out.add(issue);
        }
        return out;
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

            addReflectionIssue(reflection, vectors, pair);
        }
        publishStatus();
    }

    private void addReflectionIssue(XssReflectionEngine.Reflection reflection,
                                    List<XssVectorLibrary.Vector> vectors,
                                    HttpRequestResponse pair) {
        addToSiteMap(buildReflectionIssue(reflection, vectors, pair));
    }

    private AuditIssue buildReflectionIssue(XssReflectionEngine.Reflection reflection,
                                            List<XssVectorLibrary.Vector> vectors,
                                            HttpRequestResponse pair) {
        AuditIssueSeverity severity = IssueReporter.severity(reflection.severity());

        StringBuilder vectorHtml = new StringBuilder();
        for (XssVectorLibrary.Vector vector : vectors) {
            vectorHtml.append("<li><code>").append(escape(vector.rendered())).append("</code> &mdash; ")
                    .append(escape(vector.note())).append("</li>");
        }
        if (vectorHtml.isEmpty()) vectorHtml.append("<li>No pre-canned vector matches the surviving character set.</li>");

        String located = (pair != null && pair.hasResponse())
                ? locatedEvidence(pair.response().toString(), reflection.start(), reflection.end(), false) : "";
        String detail = "<b>Reflected input candidate for cross-site scripting</b><br>"
                + "Parameter: <code>" + escape(reflection.parameter()) + "</code> (" + escape(reflection.type()) + ")<br>"
                + "Reflection context: " + escape(reflection.context().label()) + "<br>"
                + "Characters surviving unencoded: <code>" + escape(reflection.survivingChars().isEmpty()
                        ? "(none literal)" : reflection.survivingChars()) + "</code><br>"
                + "Occurrences: " + reflection.occurrences() + "<br>"
                + "Reflected value: <code>" + escape(reflection.valuePreview()) + "</code>" + located + "<br><br>"
                + "Context-appropriate vectors from the XSS cheat sheet to validate manually:<ul>"
                + vectorHtml + "</ul>";

        HttpRequestResponse evidence = IssueReporter.withResponseEvidence(pair, reflection.start(), reflection.end());
        return reporter.buildIfNew(
                "reflect-issue\0" + reflection.url() + "\0" + reflection.parameter()
                        + "\0" + reflection.type() + "\0" + reflection.context().label(),
                "reflected parameter (" + reflection.context().label() + ")",
                detail,
                "HTML-encode reflected values for their output context, apply a strict Content-Security-Policy, "
                        + "and avoid reflecting attacker-controlled input into scripts or URL attributes.",
                reflection.url(), severity, AuditIssueConfidence.TENTATIVE,
                "Recon Hound passively maps parameter values that are reflected into responses and classifies the sink context.",
                "Reflection is necessary but not sufficient for XSS; confirm by injecting a context-appropriate vector against an authorised target.",
                evidence
        );
    }

    private void scanMessage(String text, String location, String url, HttpRequestResponse pair) {
        if (text != null && text.length() < 800_000) {
            for (String ip : RegexHound.extractIps(text)) recordIp(ip, location);
        }
        for (RegexHound.Finding finding : regexHound.scan(text, location, url, includeInfoFindings.get())) {
            String dedupe = "hound\0" + finding.rule().id() + "\0" + finding.value() + "\0" + url;
            if (!issueDedupe.add(dedupe)) continue;

            SwingUtilities.invokeLater(() -> findingModel.add(new ReconModel.FindingRow(
                    finding.rule().severity().name(), finding.rule().provider(), finding.rule().name(),
                    location, RegexHound.redact(finding.value()), url
            )));

            addAuditIssue(finding, pair);
        }

        if (scanGfPatterns.get()) {
            for (GfPatternLoader.GfMatch match : gfPatterns.scan(text)) {
                String dedupe = "gf\0" + match.pack() + "\0" + match.value() + "\0" + url;
                if (!issueDedupe.add(dedupe)) continue;
                addSyntheticFinding("INFO", "gf", "gf:" + match.pack(), location, match.value(), url);
                reporter.report("gf-issue\0" + match.pack() + "\0" + match.value() + "\0" + url,
                        "gf pattern match (" + match.pack() + ")",
                        "<b>gf pattern <code>" + escape(match.pack()) + "</code> matched</b><br>"
                                + "Location: " + escape(location) + "<br>"
                                + "Matched value: <code>" + escape(match.value()) + "</code><br><br>"
                                + "gf packs flag parameters/patterns commonly associated with a vulnerability class "
                                + "(SSRF, LFI, redirect, SQLi, XSS, etc.). This is an attack-surface hint, not a confirmed issue.",
                        "Manually assess the flagged parameter/pattern for the associated vulnerability class.",
                        url, AuditIssueSeverity.INFORMATION, AuditIssueConfidence.TENTATIVE,
                        "Recon Hound scans in-scope traffic against community gf pattern packs to surface likely-vulnerable inputs.",
                        "gf matches are heuristic attack-surface hints; confirm exploitability manually.",
                        pair);
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
            reporter.report(
                    "active-issue\0" + finding.testClass() + "\0" + finding.parameter() + "\0" + finding.url(),
                    finding.testClass() + " (" + finding.parameter() + ")",
                    detail,
                    activeRemediation(finding.testClass()),
                    finding.url(), severity, AuditIssueConfidence.FIRM,
                    "Recon Hound actively probes parameters for SSRF, SSTI and XSS when active testing is enabled.",
                    "Confirm the impact manually and only test targets you are authorised to assess.");
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

                reporter.report(
                        "oob-issue\0" + key,
                        "out-of-band " + testClass + " interaction",
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
                        "OOB interactions are strong evidence; verify the affected functionality manually.");
            }
            publishStatus();
        } catch (Exception e) {
            api.logging().logToError("Collaborator polling failed", e);
        }
    }

    private void addSignalIssue(ResponseSignalEngine.Signal signal, String location, String url, HttpRequestResponse pair) {
        addToSiteMap(buildSignalIssue(signal, location, url, pair));
    }

    private AuditIssue buildSignalIssue(ResponseSignalEngine.Signal signal, String location, String url, HttpRequestResponse pair) {
        AuditIssueSeverity severity = IssueReporter.severity(signal.severity());

        String located = (pair != null && pair.hasResponse())
                ? locatedEvidence(pair.response().toString(), signal.start(), signal.end(), false) : "";
        String detail = "<b>Response signal: " + escape(signal.name()) + "</b><br>"
                + "Location: " + escape(location) + "<br>"
                + "Evidence: <code>" + escape(signal.value()) + "</code>" + located + "<br><br>"
                + "Recon Hound flags disclosure signals (stack traces, debug/error output, source-map "
                + "references, directory listings, internal-hostname hints) in in-scope responses.";

        HttpRequestResponse evidence = IssueReporter.withResponseEvidence(pair, signal.start(), signal.end());
        return reporter.buildIfNew(
                "signal-issue\0" + signal.name() + "\0" + signal.value() + "\0" + url,
                signal.name(),
                detail,
                "Suppress verbose errors and stack traces in production, remove source-map references from "
                        + "public assets, disable directory listing, and avoid leaking internal hostnames.",
                url, severity, AuditIssueConfidence.FIRM,
                "Recon Hound passively inspects in-scope responses for information-disclosure signals.",
                "Disclosure findings are heuristic; confirm the leaked content is sensitive before reporting.",
                evidence
        );
    }

    private void recordAsset(String host, String source) {
        if (host == null || host.isBlank()) return;
        if (isIpLiteral(host)) { recordIp(host, source); return; }
        String value = host.toLowerCase(Locale.ROOT);
        if (assetHosts.add(value)) {
            SwingUtilities.invokeLater(() -> assetModel.add(new ReconModel.AssetRow("host", value, source)));
        }
    }

    private void recordIp(String ip, String source) {
        if (ip == null || ip.isBlank()) return;
        String value = ip.startsWith("[") && ip.endsWith("]") ? ip.substring(1, ip.length() - 1) : ip;
        if (assetIps.add(value)) {
            String type = value.contains(":") ? "ipv6" : "ipv4";
            SwingUtilities.invokeLater(() -> assetModel.add(new ReconModel.AssetRow(type, value, source)));
        }
    }

    private static boolean isIpLiteral(String host) {
        String h = host.startsWith("[") && host.endsWith("]") ? host.substring(1, host.length() - 1) : host;
        return h.matches("\\d{1,3}(?:\\.\\d{1,3}){3}") || h.contains(":");
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
        addToSiteMap(buildRegexIssue(finding, pair));
    }

    private AuditIssue buildRegexIssue(RegexHound.Finding finding, HttpRequestResponse pair) {
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

        // Mark the matched bytes on the correct side; the offsets are message-relative (scanMessage
        // scans request.toString()/response.toString()). Skip reconstructed source-map text — its
        // offsets don't map to any live message.
        String loc = finding.location() == null ? "" : finding.location();
        boolean sourceMap = loc.startsWith("source-map");
        boolean requestSide = loc.contains("request");
        HttpRequestResponse evidence = pair;
        String located = "";
        if (!sourceMap && pair != null) {
            if (requestSide && pair.request() != null) {
                evidence = IssueReporter.withRequestEvidence(pair, finding.start(), finding.end());
                located = locatedEvidence(pair.request().toString(), finding.start(), finding.end(), true);
            } else if (!requestSide && pair.hasResponse()) {
                evidence = IssueReporter.withResponseEvidence(pair, finding.start(), finding.end());
                located = locatedEvidence(pair.response().toString(), finding.start(), finding.end(), true);
            }
        }

        String detail = "<b>Regex Hound match</b><br>"
                + "Provider: " + escape(finding.rule().provider()) + "<br>"
                + "Location: " + escape(finding.location()) + "<br>"
                + "Matched value: <code>" + escape(RegexHound.redact(finding.value())) + "</code><br>"
                + "Entropy: " + String.format(Locale.ROOT, "%.2f", finding.entropy()) + located + "<br><br>"
                + "Review the original request/response and validate whether the credential or token is live.";

        return reporter.buildIfNew(
                "hound-issue\0" + finding.rule().id() + "\0" + finding.value() + "\0" + finding.url(),
                finding.rule().name(),
                detail,
                "Remove exposed credentials from client-visible content, rotate affected secrets, and constrain their privileges.",
                finding.url(), severity, confidence,
                "Recon Hound identifies credential, token, key, and security-relevant patterns in in-scope HTTP traffic.",
                "Secret scanning is heuristic; verify context before remediation.",
                evidence
        );
    }

    /**
     * Renders a located-evidence HTML block: line number, byte range, and a &plusmn;40-char context
     * window with the matched span delimited. Returns "" when the offsets are unusable. The span is
     * redacted for secrets so it stays masked in text while the marker still points Burp at the bytes.
     */
    private static String locatedEvidence(String message, int start, int end, boolean redact) {
        if (message == null || start < 0 || end <= start || start >= message.length()) return "";
        int e = Math.min(end, message.length());
        if (e <= start) return "";
        int line = 1;
        for (int i = 0; i < start; i++) if (message.charAt(i) == '\n') line++;
        int ctxStart = Math.max(0, start - 40);
        int ctxEnd = Math.min(message.length(), e + 40);
        String span = message.substring(start, e);
        if (redact) span = RegexHound.redact(span);
        return "<br><b>Location:</b> line " + line + ", bytes " + start + "&ndash;" + e
                + " (highlighted in the message viewer above)<br><code>"
                + escape(message.substring(ctxStart, start))
                + "&#187;<b>" + escape(span) + "</b>&#171;"
                + escape(message.substring(e, ctxEnd)) + "</code>";
    }

    private void addToSiteMap(AuditIssue issue) {
        if (issue != null) api.siteMap().add(issue);
    }

    /**
     * Passive detection entry point for Burp's scan pipeline. Runs Recon Hound's passive engines
     * against a base request/response and returns freshly-built audit issues, deduplicated against
     * everything the extension has already filed (shared {@link IssueReporter} dedupe). Does not add
     * to the site map — Burp's scanner registers the returned issues. Called from {@link ReconScanCheck}.
     */
    List<AuditIssue> passiveAuditIssues(HttpRequestResponse rr) {
        List<AuditIssue> issues = new ArrayList<>();
        if (rr == null || rr.request() == null || !rr.hasResponse() || rr.response() == null) return issues;
        HttpRequest request = rr.request();
        HttpResponse response = rr.response();
        String url = request.url();
        try {
            for (RegexHound.Finding f : regexHound.scan(response.toString(), "scan-response", url, includeInfoFindings.get())) {
                addIfPresent(issues, buildRegexIssue(f, rr));
            }
            for (RegexHound.Finding f : regexHound.scan(request.toString(), "scan-request", url, includeInfoFindings.get())) {
                addIfPresent(issues, buildRegexIssue(f, rr));
            }
            for (WebHygieneEngine.Note note : webHygiene.analyze(request, response)) {
                addIfPresent(issues, buildHygieneIssue(note, url, rr));
            }
            for (ResponseSignalEngine.Signal signal : responseSignals.analyze(response)) {
                addIfPresent(issues, buildSignalIssue(signal, "scan-response", url, rr));
            }
            for (XssReflectionEngine.Reflection reflection : xssReflectionEngine.analyze(request, response)) {
                addIfPresent(issues, buildReflectionIssue(reflection, reflection.viableVectors(), rr));
            }
            issues.addAll(scaIssues(url, response.bodyToString(), rr));
            issues.addAll(domXssIssues(url, response.bodyToString(), rr));
        } catch (Exception e) {
            api.logging().logToError("Passive audit failed for " + url, e);
        }
        return issues;
    }

    private static void addIfPresent(List<AuditIssue> list, AuditIssue issue) {
        if (issue != null) list.add(issue);
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
