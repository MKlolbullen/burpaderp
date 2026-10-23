package com.victor.reconloop;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import javax.swing.*;
import java.io.IOException;
import java.io.Reader;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

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
    private final LlmClient llmClient;
    /** Global AI-activity feed: capped, in-memory, EDT-confined (every read/write is marshalled). */
    private final AiFeed.Store aiFeed = new AiFeed.Store();
    private volatile java.util.function.Consumer<AiFeed.Event> aiFeedListener;
    private final CertificateTransparencyClient ctClient;
    private final ParameterDiscoveryEngine parameterDiscovery;
    private final ActiveTestEngine activeTestEngine;
    private final CorpusFuzzEngine corpusFuzzEngine;
    private volatile SqlmapClient sqlmapClient;
    private final IssueReporter reporter;
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
    private final Set<String> sidecarAssetDedupe = ConcurrentHashMap.newKeySet();
    private final Set<String> assetHosts = ConcurrentHashMap.newKeySet();
    private final Set<String> assetIps = ConcurrentHashMap.newKeySet();
    private final Map<String, HttpRequest> originTemplates = new ConcurrentHashMap<>();

    private final ExecutorService worker = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "Burp-Recon-Hound");
        t.setDaemon(true);
        return t;
    });

    private final ExecutorService activeWorker;

    private final ExecutorService domainReconWorker = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "Burp-Recon-Hound-Domain"); t.setDaemon(true); return t;
    });
    private final ExecutorService assetWorker = Executors.newSingleThreadExecutor(r -> {
        Thread t=new Thread(r,"Burp-Recon-Hound-Assets");t.setDaemon(true);return t;
    });

    private static ExecutorService newActiveWorker() {
        return Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "Burp-Recon-Hound-Active");
            t.setDaemon(true);
            return t;
        });
    }

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

    private final ThreadLocal<ScanRun> observationRun = new ThreadLocal<>();
    private final RunHistory runHistory = new RunHistory();
    private final NativeRunRegistry activeRuns = new NativeRunRegistry(false, runHistory::register);
    private final NativeRunRegistry crawlRuns = new NativeRunRegistry(true, runHistory::register);
    private final NativeRunRegistry domainRuns = new NativeRunRegistry(true, runHistory::register);
    private ScanRun crawlRun; // guarded by crawlRuns
    private int previousCrawlUsage; // retired sessions; pause/resume never refills the crawl cap
    private final ActiveRequestGateway.Sender targetTransport;
    private final DestinationGuard targetDestinations;

    private final AtomicBoolean running = new AtomicBoolean(true);
    private final AtomicBoolean crawlEnabled = new AtomicBoolean(true);
    private final AtomicBoolean addToScope = new AtomicBoolean(true);
    private final AtomicBoolean sameOriginOnly = new AtomicBoolean(true);
    private final AtomicBoolean includeInfoFindings = new AtomicBoolean(false);
    private final AtomicBoolean scanGfPatterns = new AtomicBoolean(true);
    private final AtomicBoolean followRedirects = new AtomicBoolean(true);
    private final AtomicBoolean detectReflections = new AtomicBoolean(true);
    private final AtomicBoolean activeTestsEnabled = new AtomicBoolean(false);
    private final AtomicBoolean mutatingActiveRequests = new AtomicBoolean(false);
    private final AtomicBoolean oastActiveRequests = new AtomicBoolean(false);
    private final AtomicBoolean persistentPayloadActiveRequests = new AtomicBoolean(false);
    private final AtomicBoolean timeDelayActiveRequests = new AtomicBoolean(false);
    private final AtomicBoolean uploadActiveRequests = new AtomicBoolean(false);
    private final AtomicBoolean authLockoutActiveRequests = new AtomicBoolean(false);
    private final AtomicInteger maxRequests = new AtomicInteger(500);
    private final AtomicInteger maxRedirects = new AtomicInteger(8);
    private final AtomicInteger activeThrottleMillis = new AtomicInteger(150);
    private final AtomicInteger activeRequestBudget = new AtomicInteger(60);
    private final AtomicInteger activePerHostBudget = new AtomicInteger(60);
    private final AtomicInteger activePerEndpointBudget = new AtomicInteger(20);
    private final AtomicInteger activePerProbeBudget = new AtomicInteger(20);
    private final AtomicInteger sentRequests = new AtomicInteger(0);

    private volatile StatusListener statusListener = s -> {};

    ReconController(MontoyaApi api,
                    ReconModel.FindingTableModel findingModel,
                    ReconModel.DiscoveryTableModel discoveryModel,
                    ReconModel.ParameterTableModel parameterModel,
                    ReconModel.ReflectionTableModel reflectionModel,
                    ReconModel.ActiveTableModel activeModel,
                    ReconModel.AssetTableModel assetModel) {
        this(api, findingModel, discoveryModel, parameterModel, reflectionModel, activeModel,
                assetModel, newActiveWorker(), true);
    }

    ReconController(MontoyaApi api,
                    ReconModel.FindingTableModel findingModel,
                    ReconModel.DiscoveryTableModel discoveryModel,
                    ReconModel.ParameterTableModel parameterModel,
                    ReconModel.ReflectionTableModel reflectionModel,
                    ReconModel.ActiveTableModel activeModel,
                    ReconModel.AssetTableModel assetModel,
                    ExecutorService activeWorker, boolean startBackgroundWorkers) {
        this(api, findingModel, discoveryModel, parameterModel, reflectionModel, activeModel, assetModel,
                activeWorker, startBackgroundWorkers, DestinationGuard.system());
    }

    ReconController(MontoyaApi api, ReconModel.FindingTableModel findingModel,
                    ReconModel.DiscoveryTableModel discoveryModel, ReconModel.ParameterTableModel parameterModel,
                    ReconModel.ReflectionTableModel reflectionModel, ReconModel.ActiveTableModel activeModel,
                    ReconModel.AssetTableModel assetModel, ExecutorService activeWorker, boolean startBackgroundWorkers,
                    DestinationGuard destinations) {
        this(api, findingModel, discoveryModel, parameterModel, reflectionModel, activeModel, assetModel,
                activeWorker, startBackgroundWorkers, destinations, new LlmClient());
    }

    ReconController(MontoyaApi api, ReconModel.FindingTableModel findingModel,
                    ReconModel.DiscoveryTableModel discoveryModel, ReconModel.ParameterTableModel parameterModel,
                    ReconModel.ReflectionTableModel reflectionModel, ReconModel.ActiveTableModel activeModel,
                    ReconModel.AssetTableModel assetModel, ExecutorService activeWorker, boolean startBackgroundWorkers,
                    DestinationGuard destinations, LlmClient llmClient) {
        this.llmClient = Objects.requireNonNull(llmClient);
        this.activeWorker = Objects.requireNonNull(activeWorker, "activeWorker");
        this.api = api;
        this.targetTransport = new MontoyaTargetTransport(api, destinations);
        this.targetDestinations=destinations;
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
        this.corpusFuzzEngine = new CorpusFuzzEngine(api, payloadLibrary, activeThrottleMillis.get());
        try {
            this.store = api.persistence().extensionData();
            restoreState();
        } catch (Exception e) {
            api.logging().logToError("Persisted-state restore skipped", e);
        }
        this.sqlmapClient = new SqlmapClient(null);
        if (startBackgroundWorkers) {
            worker.submit(this::workerLoop);
            oobPoller.scheduleWithFixedDelay(this::pollCollaborator, 12, 12, TimeUnit.SECONDS);
            oobPoller.scheduleWithFixedDelay(this::saveState, 60, 60, TimeUnit.SECONDS);
        }
    }

    private final Object stateWriteLock = new Object();
    private final java.util.concurrent.atomic.AtomicLong stateGeneration = new java.util.concurrent.atomic.AtomicLong();
    private final java.util.concurrent.atomic.AtomicLong snapshotSequence = new java.util.concurrent.atomic.AtomicLong();
    private long lastSavedSnapshot;
    private record StateSnapshot(long generation, long sequence, List<ReconModel.FindingRow> findings,
                                 List<ReconModel.AssetRow> assets, List<ReconModel.ActiveRow> active, List<RunRecord> runs) {}

    private StateSnapshot snapshot(long generation) {
        return new StateSnapshot(generation, snapshotSequence.incrementAndGet(), findingModel.snapshot(), assetModel.snapshot(), activeModel.snapshot(), runHistory.snapshot());
    }

    private void writeSnapshot(StateSnapshot snapshot) {
        if (store == null) return;
        synchronized (stateWriteLock) {
            if (snapshot.generation() != stateGeneration.get() || snapshot.sequence() <= lastSavedSnapshot) return;
            PersistedState.saveStrings(store, PersistedState.K_FILED, reporter.filedSnapshot());
            PersistedState.saveStrings(store, PersistedState.K_HOSTS, new ArrayList<>(assetHosts));
            PersistedState.saveStrings(store, PersistedState.K_IPS, new ArrayList<>(assetIps));
            PersistedState.saveFindings(store, snapshot.findings());
            PersistedState.saveAssets(store, snapshot.assets());
            if (!PersistedState.saveActiveEvidence(store, snapshot.active()))
                api.logging().logToOutput("[Recon Hound] Active evidence snapshot preserved: unsupported or corrupt format.");
            if (!PersistedState.saveRunHistory(store, snapshot.runs()))
                api.logging().logToOutput("[Recon Hound] Scan-run history preserved: unsupported or corrupt format.");
            lastSavedSnapshot = snapshot.sequence();
        }
    }

    /** Restores dedupe keys, asset inventory, and Findings/Hosts rows from the Burp project. */
    private void restoreState() {
        if (store == null) return;
        var runs = PersistedState.loadRunHistory(store);
        runHistory.restore(runs.runs());
        if (!runs.writable()) api.logging().logToOutput("[Recon Hound] Scan-run history unsupported/corrupt; preserved without overwrite.");
        reporter.restore(PersistedState.loadStrings(store, PersistedState.K_FILED));
        assetHosts.addAll(PersistedState.loadStrings(store, PersistedState.K_HOSTS));
        assetIps.addAll(PersistedState.loadStrings(store, PersistedState.K_IPS));
        List<ReconModel.FindingRow> findings = PersistedState.loadFindings(store);
        List<ReconModel.AssetRow> assets = PersistedState.loadAssets(store);
        ActiveEvidenceCodec.Loaded active = PersistedState.loadActiveEvidence(store);
        if (!active.writable()) api.logging().logToOutput("[Recon Hound] Active evidence is unsupported/corrupt; preserved without automatic overwrite.");
        for (var row : active.rows()) if (row.evidenceRecord().observation() != null && row.verificationState() == VerificationState.CONFIRMED)
            oobDedupe.add(row.evidenceRecord().observation().fingerprint());
        if (findings.isEmpty() && assets.isEmpty() && active.rows().isEmpty()) return;
        SwingUtilities.invokeLater(() -> {
            for (int i = findings.size() - 1; i >= 0; i--) findingModel.add(findings.get(i));
            for (int i = assets.size() - 1; i >= 0; i--) assetModel.add(assets.get(i));
            for (int i = active.rows().size() - 1; i >= 0; i--) activeModel.add(active.rows().get(i));
        });
        api.logging().logToOutput("[Recon Hound] Restored " + findings.size() + " finding(s) and "
                + (assetHosts.size() + assetIps.size()) + " asset(s) from the Burp project.");
    }

    /** Only copy model references on the EDT; encoding/writes use the existing background saver. */
    private void saveState() {
        if (store == null || !running.get()) return;
        long generation = stateGeneration.get();
        SwingUtilities.invokeLater(() -> {
            if (!running.get() || generation != stateGeneration.get()) return;
            StateSnapshot snapshot = snapshot(generation);
            try {
                oobPoller.execute(() -> {
                    try { writeSnapshot(snapshot); }
                    catch (Exception e) { api.logging().logToError("Persisted-state save failed", e); }
                });
            } catch (java.util.concurrent.RejectedExecutionException unloading) { /* final synchronous save owns unload */ }
        });
    }

    interface StatusListener { void update(String status); }
    record QueueItem(URI uri, URI rootOrigin, String source) {}

    void setStatusListener(StatusListener listener) { this.statusListener = listener == null ? s -> {} : listener; }
    void setCrawlEnabled(boolean value) {
        synchronized (crawlRuns) {
            crawlEnabled.set(value);
            crawlRuns.setEnabled(value);
            if (!value && crawlRun != null) {
                previousCrawlUsage += crawlRun.requestBudget().used();
                sentRequests.set(previousCrawlUsage);
                crawlRun = null;
            }
        }
    }
    void setAddToScope(boolean value) { addToScope.set(value); }
    void setSameOriginOnly(boolean value) { sameOriginOnly.set(value); }
    void setIncludeInfoFindings(boolean value) { includeInfoFindings.set(value); }
    void setScanGfPatterns(boolean value) { scanGfPatterns.set(value); }
    void setFollowRedirects(boolean value) { followRedirects.set(value); }
    void setDetectReflections(boolean value) { detectReflections.set(value); }
    void setActiveTestsEnabled(boolean value) {
        synchronized (activeRuns) {
            activeRuns.setEnabled(value);
            activeTestsEnabled.set(value);
        }
    }
    void setMutatingActiveRequests(boolean value) { setActivePermission(mutatingActiveRequests, value); }
    void setOastActiveRequests(boolean value) { setActivePermission(oastActiveRequests, value); }
    void setPersistentPayloadActiveRequests(boolean value) { setActivePermission(persistentPayloadActiveRequests, value); }
    void setTimeDelayActiveRequests(boolean value) { setActivePermission(timeDelayActiveRequests, value); }
    void setUploadActiveRequests(boolean value) { setActivePermission(uploadActiveRequests, value); }
    void setAuthLockoutActiveRequests(boolean value) { setActivePermission(authLockoutActiveRequests, value); }
    private void setActivePermission(AtomicBoolean permission, boolean value) {
        synchronized (activeRuns) {
            if (permission.getAndSet(value) != value) activeRuns.invalidate();
        }
    }

    void setMaxRequests(int value) { maxRequests.set(Math.max(1, value)); }
    void setMaxRedirects(int value) { maxRedirects.set(Math.max(0, value)); }
    void setActiveRequestBudget(int value) { activeRequestBudget.set(Math.max(1, value)); }
    void setActivePerHostBudget(int value) { activePerHostBudget.set(Math.max(1, value)); }
    void setActivePerEndpointBudget(int value) { activePerEndpointBudget.set(Math.max(1, value)); }
    void setActivePerProbeBudget(int value) { activePerProbeBudget.set(Math.max(1, value)); }

    private ScanRun.RequestLimits activeRequestLimits() {
        return new ScanRun.RequestLimits(
                activeRequestBudget.get(),
                activePerHostBudget.get(),
                activePerEndpointBudget.get(),
                activePerProbeBudget.get());
    }

    private ScanRun.RequestLimits activeRequestLimits(int globalCap) {
        int global = Math.min(Math.max(0, globalCap), activeRequestBudget.get());
        return new ScanRun.RequestLimits(
                global,
                Math.min(activePerHostBudget.get(), Math.max(1, global)),
                Math.min(activePerEndpointBudget.get(), Math.max(1, global)),
                Math.min(activePerProbeBudget.get(), Math.max(1, global)));
    }

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
            corpusFuzzEngine.setCollaborator(collaborator);
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

    /**
     * Looks the domain up in public scan and passive-DNS datasets. Requests go only to those
     * providers. Discovered names and addresses are recorded in the asset inventory and are not
     * crawled.
     */
    void lookupPassiveOsint(String domain) {
        activeWorker.submit(() -> {
            String root = CertificateTransparencyClient.normalizeDomain(domain);
            if (root == null) {
                api.logging().logToError("Invalid domain for passive OSINT: " + domain);
                return;
            }
            api.logging().logToOutput("[Recon Hound] Passive OSINT for " + root
                    + " (Shodan, Censys, VirusTotal, FOFA; no traffic to the target).");
            PassiveOsintClient client = new PassiveOsintClient();
            int recorded = 0;
            for (PassiveOsintClient.Provider provider : PassiveOsintClient.Provider.values()) {
                String key = System.getenv(provider.envVar);
                PassiveOsintClient.LookupResult result = client.lookup(provider, root, key);
                if (provider == PassiveOsintClient.Provider.VIRUSTOTAL && key != null && !key.isBlank()) {
                    result = mergeOsint(result, client.lookupVirusTotalResolutions(root, key));
                }
                for (String note : result.notes()) {
                    api.logging().logToOutput("[Recon Hound] " + note);
                }
                for (PassiveOsintClient.Observation observation : result.observations()) {
                    if ("host".equals(observation.kind())) recordAsset(observation.value(), observation.source());
                    else recordIp(observation.value(), observation.source());
                    recorded++;
                }
            }
            api.logging().logToOutput("[Recon Hound] Passive OSINT recorded " + recorded
                    + " host/IP observation(s) for " + root + ".");
            publishStatus();
        });
    }

    private static PassiveOsintClient.LookupResult mergeOsint(PassiveOsintClient.LookupResult first,
                                                               PassiveOsintClient.LookupResult second) {
        List<PassiveOsintClient.Observation> observations = new ArrayList<>(first.observations());
        observations.addAll(second.observations());
        List<String> notes = new ArrayList<>(first.notes());
        notes.addAll(second.notes());
        return new PassiveOsintClient.LookupResult(observations, notes);
    }

    void discoverParameters(String url) {
        if (!activeTestsEnabled.get()) {
            api.logging().logToOutput("[Recon Hound] Parameter discovery sends active traffic; enable the opt-in checkbox first.");
            return;
        }
        submitNativeActive(ticket -> {
            String target = url == null ? "" : url.trim();
            if (!target.startsWith("http")) { api.logging().logToError("Invalid parameter-discovery URL: " + target); return; }
            if (!api.scope().isInScope(target)) { api.logging().logToError("Target not in scope: " + target); return; }
            HttpRequest base = httpRequestFromUrl(target);
            ScanRun run = activeRuns.begin(ticket, ScanProfile.ACTIVE_SAFE, ScopeSnapshot.forTargetUrl(target),
                    activeRequestLimits());
            ActiveRequestGateway gateway = new ActiveRequestGateway(
                    RequestPolicy.safeDefault(api.scope()::isInScope), targetTransport);
            api.logging().logToOutput("[Recon Hound] Arjun-style parameter discovery on " + target
                    + " (" + parameterDiscovery.wordlistSize() + " candidates, run " + run.id() + ")");
            try {
                for (ParameterDiscoveryEngine.Discovered found :
                        parameterDiscovery.discover(base, run, gateway, activeThrottleMillis.get())) {
                    addActiveRow("INFO", "PARAM", found.name(), "discovered", found.evidence(), found.url(), found.evidenceRecord());
                }
            } finally {
                run.complete();
                api.logging().logToOutput("[Recon Hound] Parameter-discovery run " + run.id() + " ended "
                        + run.status().name().toLowerCase(Locale.ROOT) + " after " + run.requestBudget().used()
                        + "/" + run.requestBudget().limit() + " request(s).");
            }
            publishStatus();
        });
    }

    /** Separate worker for the fixed passive sidecar; it never occupies the target request queue. */
    Future<?> enumerateDomain(DomainReconProcess.Plan plan, Consumer<DomainReconProcess.Event> events,
                              Consumer<DomainReconProcess.Outcome> completion) {
        NativeRunRegistry.Ticket ticket=domainRuns.ticket();
        return domainReconWorker.submit(() -> {
            var outcome = new DomainReconProcess().run(plan, event -> SwingUtilities.invokeLater(() -> events.accept(event)));
            String sidecarState=outcome.state(),nativeState="SKIPPED";int nativeDispatches=0;
            if(plan.workflow()&&plan.httpBudget()>0&&Set.of("SUCCESS","PARTIAL").contains(outcome.state())) {
                ScanRun run=domainRuns.begin(ticket,ScanProfile.DISCOVERY,new ScopeSnapshot(Set.of(plan.domain()),Set.of()),
                        new ScanRun.RequestLimits(plan.httpBudget(),plan.perHost(),3,plan.httpBudget()));
                try {
                    var inputs=ReconWorkflowInputs.load(plan);
                    var gateway=new ActiveRequestGateway(RequestPolicy.safeDefault(url -> NativeReconChain.canonical(url,plan.domain())!=null&&api.scope().isInScope(url)),
                            new MontoyaTargetTransport(api,targetDestinations,15000));
                    var nativeResult=new NativeReconChain(gateway,url->httpRequestFromUrl(url).withMethod("GET")).run(plan,inputs,run,
                            event->SwingUtilities.invokeLater(()->events.accept(event)));
                    String state=nativeResult.state().equals("SUCCESS")?outcome.state():nativeResult.state().equals("FAILED")?"PARTIAL":nativeResult.state();
                    nativeState=nativeResult.state();nativeDispatches=nativeResult.dispatched();
                    outcome=new DomainReconProcess.Outcome(state,outcome.count(),outcome.detail()+" Native phase: "+nativeResult.dispatched()+" dispatches; "+nativeResult.responses()+" responses. "+nativeResult.detail());
                } catch(Exception e){run.fail("workflow inputs or native phase failed");nativeState="FAILED";outcome=new DomainReconProcess.Outcome("PARTIAL",outcome.count(),"Native inputs or HTTP phase failed validation; provider artifacts remain available.");}
                finally {domainRuns.finish(ticket);}
            }
            boolean interrupted=Thread.interrupted();
            try {
                if(Files.isDirectory(plan.runDir(),java.nio.file.LinkOption.NOFOLLOW_LINKS))NativeReconChain.writeJson(plan.runDir().resolve("chain-result.json"),Map.of("schema_version",1,"workflow_run_id",plan.runId(),"state",outcome.state(),"sidecar_state",sidecarState,"native_state",nativeState,"native_dispatches",nativeDispatches,"host_candidates",outcome.count(),"native_http_enabled",plan.httpBudget()>0));
            }catch(IOException e){outcome=new DomainReconProcess.Outcome("FAILED",outcome.count(),"Could not save the overall chain result; partial phase artifacts remain.");}
            finally {if(interrupted)Thread.currentThread().interrupt();}
            var finished=outcome;
            SwingUtilities.invokeLater(() -> completion.accept(finished));
        });
    }

    /**
     * Imports already-normalized Go-sidecar JSONL without launching any process or sending target
     * traffic. Every line is bounded and checked against the current Burp scope again.
     */
    void importSidecarJsonl(Path path, Consumer<String> completion) {
        if (path == null) {
            deliverImportCompletion(completion, "[error] Choose a reconctl JSONL file first.");
            return;
        }
        assetWorker.submit(() -> {
            ScanRun run = ScanRun.begin(ScanProfile.EXTERNAL_TOOL, ScopeSnapshot.empty(), 0);
            runHistory.register(run);
            try (Reader reader = Files.newBufferedReader(path)) {
                SidecarEventImporter.ImportResult result = SidecarEventImporter.importJsonl(reader,
                        this::sidecarEventInScope, event -> {
                            observationRun.set(run);
                            try { materializeSidecarEvent(event, run.id()); } finally { observationRun.remove(); }
                        });
                run.complete();
                String summary = "Imported " + result.accepted() + " typed sidecar record(s); rejected "
                        + result.rejected() + ". Run " + run.id() + ".";
                api.logging().logToOutput("[Recon Hound] " + summary);
                if (!result.rejectionReasons().isEmpty()) {
                    api.logging().logToOutput("[Recon Hound] Sidecar import rejection sample: "
                            + result.rejectionReasons().get(0));
                }
                publishStatus();
                deliverImportCompletion(completion, summary);
            } catch (IOException e) {
                run.fail("sidecar JSONL read failed");
                String message = "[error] Failed to import sidecar JSONL: " + e.getMessage();
                api.logging().logToError("Sidecar JSONL import failed", e);
                deliverImportCompletion(completion, message);
            }
        });
    }

    private void deliverImportCompletion(Consumer<String> completion, String message) {
        if (completion == null) return;
        SwingUtilities.invokeLater(() -> completion.accept(message));
    }

    private boolean sidecarEventInScope(SidecarEvent.Event event) {
        for (String candidate : event.scopeCandidates()) {
            try {
                if (api.scope().isInScope(candidate)) return true;
            } catch (Exception ignored) {
                // Scope predicates are treated as fail-closed at this external boundary.
            }
        }
        return false;
    }

    private void materializeSidecarEvent(SidecarEvent.Event event, UUID importRunId) {
        String sidecarRun = event.runId() == null || event.runId().isBlank() ? "unlabelled" : event.runId();
        String source = "reconctl:" + event.tool() + " sidecar-run=" + sidecarRun + " import-run=" + importRunId;
        switch (event.kind()) {
            case DOMAIN, HOSTNAME -> recordAsset(event.hostname(), source);
            case RESOLVED_HOST -> {
                recordAsset(event.hostname(), source);
                event.addresses().forEach(address -> recordIp(address, source));
                event.cnames().forEach(cname -> recordAsset(cname, source));
            }
            case IP -> recordIp(event.ip(), source);
            case SERVICE -> recordSidecarService(event, source);
            case HTTP_TARGET, URL -> recordImportedUrl(event.url(), source);
            case PARAMETERIZED_URL -> {
                recordImportedUrl(event.url(), source);
                String key = "sidecar\0" + event.url() + "\0" + event.parameter();
                if (parameterDedupe.add(key)) {
                    SwingUtilities.invokeLater(() -> parameterModel.add(new ReconModel.ParameterRow(
                            0, "sidecar", event.parameter(), "external discovery", "", event.url())));
                }
            }
            case FINDING -> materializeSidecarFinding(event, source);
            case CIDR, PAYLOAD -> throw new IllegalArgumentException("non-materializable sidecar kind reached controller");
        }
    }

    private void recordSidecarService(SidecarEvent.Event event, String source) {
        String host = event.ip() == null || event.ip().isBlank() ? event.hostname() : event.ip();
        if (host == null || host.isBlank()) return;
        recordAsset(host, source);
        String value = host + ":" + event.port() + "/" + (event.protocol() == null || event.protocol().isBlank()
                ? "tcp" : event.protocol());
        if (sidecarAssetDedupe.add("service\0" + value)) {
            SwingUtilities.invokeLater(() -> assetModel.add(new ReconModel.AssetRow("service", value, source)));
        }
    }

    /** Adds an imported URL to inventory without queueing it, changing scope, or sending traffic. */
    private void recordImportedUrl(String url, String source) {
        try {
            URI uri = URI.create(url);
            if (uri.getHost() == null) return;
            recordAsset(uri.getHost(), source);
            if (discoveredUrls.add(uri.toString())) {
                String kind = InterestingResourceCatalog.classify(uri);
                SwingUtilities.invokeLater(() -> discoveryModel.add(new ReconModel.DiscoveryRow(kind, uri.toString(), source)));
            }
        } catch (IllegalArgumentException ignored) {
            // The parser validates URL syntax first; retain this defensive guard at the materialization boundary.
        }
    }

    private void materializeSidecarFinding(SidecarEvent.Event event, String source) {
        recordImportedUrl(event.url(), source);
        String evidence = event.evidence() == null || event.evidence().isBlank()
                ? "No tool evidence was included in this sidecar record." : RegexHound.redact(event.evidence());
        String provider = "sidecar:" + event.tool();
        addSyntheticFinding(event.severity(), provider, "external finding", "sidecar", evidence, event.url());
        reporter.report(
                "sidecar-finding\0" + event.tool() + "\0" + event.severity() + "\0" + event.url() + "\0" + evidence,
                "External " + event.tool() + " finding",
                "<b>Imported typed sidecar finding</b><br>Tool: <code>" + escape(event.tool()) + "</code><br>"
                        + "Target: <code>" + escape(event.url()) + "</code><br>Evidence: " + escape(evidence),
                "Reproduce the finding in Burp and remediate the affected endpoint or configuration.",
                event.url(), IssueReporter.severity(event.severity()), AuditIssueConfidence.TENTATIVE,
                "Recon Hound imported a contract-validated external-tool result through the Go recon sidecar.",
                "External tool output is evidence, not final proof. Reproduce the result in the current Burp session.");
    }

    private List<HttpRequest> parameterizedTargets() {
        return api.siteMap().requestResponses().stream().map(HttpRequestResponse::request)
                .filter(Objects::nonNull).filter(HttpRequest::isInScope).filter(HttpRequest::hasParameters)
                .collect(java.util.stream.Collectors.toMap(HttpRequest::url, r -> r, (a, b) -> a, LinkedHashMap::new))
                .values().stream().toList();
    }

    private record JwtTarget(HttpRequest request, String token) {}

    private List<JwtTarget> jwtTargets() {
        List<JwtTarget> targets = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
            HttpRequest req = rr.request();
            if (req == null || !req.isInScope() || !SAFE_METHODS.contains(req.method().toUpperCase(Locale.ROOT))) continue;
            for (String token : JwtAttackEngine.extractJwts(req)) {
                if (seen.add(req.url() + "\0" + token)) targets.add(new JwtTarget(req, token));
            }
        }
        return targets;
    }

    private List<HttpRequestResponse> accessControlTargets() {
        return api.siteMap().requestResponses().stream()
                .filter(rr -> rr.request() != null && rr.hasResponse() && rr.response() != null)
                .filter(rr -> rr.request().isInScope())
                .filter(rr -> SAFE_METHODS.contains(rr.request().method().toUpperCase(Locale.ROOT)))
                .collect(java.util.stream.Collectors.toMap(rr -> rr.request().method() + " " + rr.request().url(),
                        rr -> rr, (a, b) -> a, LinkedHashMap::new)).values().stream().toList();
    }

    void runActiveTests() {
        if (!activeTestsEnabled.get()) {
            api.logging().logToOutput("[Recon Hound] Active tests are disabled; enable the opt-in checkbox first.");
            return;
        }
        if (oastActiveRequests.get()) ensureCollaborator();
        submitNativeActive(ticket -> {
            List<HttpRequest> targets = parameterizedTargets();

            boolean allowMutating = mutatingActiveRequests.get();
            ScanProfile profile = allowMutating ? ScanProfile.ACTIVE_MUTATION : ScanProfile.ACTIVE_SAFE;
            ScanRun run = activeRuns.begin(ticket, profile, ScopeSnapshot.forTargets(targets.stream().map(HttpRequest::url).toList()), activeRequestLimits());
            ActiveRequestGateway gateway = newTargetGateway(allowMutating);
            api.logging().logToOutput("[Recon Hound] Active testing " + targets.size()
                    + " in-scope parameterised request(s) with quotas global/host/endpoint/probe="
                    + run.requestLimits().global() + "/" + run.requestLimits().perHost() + "/"
                    + run.requestLimits().perEndpoint() + "/" + run.requestLimits().perProbe()
                    + (allowMutating ? " including non-safe methods." : " using safe methods only.")
                    + " Risk grants=[OAST=" + oastActiveRequests.get()
                    + ", persistent-payload=" + persistentPayloadActiveRequests.get()
                    + ", time-delay=" + timeDelayActiveRequests.get()
                    + ", upload=" + uploadActiveRequests.get()
                    + ", auth/lockout=" + authLockoutActiveRequests.get() + "]"
                    + " Run=" + run.id());
            try {
                for (HttpRequest base : targets) {
                    if (!activeTestsEnabled.get()) {
                        run.cancel();
                        break;
                    }
                    if (run.requestBudget().exhausted()) break;
                    for (ActiveTestEngine.ActiveFinding finding : activeTestEngine.test(base, run, gateway)) {
                        if (activeRuns.isCurrent(ticket)) reportActiveFinding(finding, base);
                    }
                    publishStatus();
                }
            } finally {
                if (run.isActive()) run.complete();
            }
            api.logging().logToOutput("[Recon Hound] Active testing pass complete: "
                    + run.requestBudget().used() + "/" + run.requestBudget().limit()
                    + " request(s), status=" + run.status() + ", run=" + run.id()
                    + ". OOB results may arrive asynchronously.");
        });
    }

    RunHistory runHistory() { return runHistory; }

    boolean controlRun(String id, String action) {
        boolean changed = runHistory.control(id, action);
        if (changed) saveState();
        return changed;
    }

    boolean retryFailedProbes(String parentId) {
        if (!activeTestsEnabled.get() || runHistory.retries(parentId).isEmpty()) return false;
        submitNativeActive(ticket -> {
            var plan = RunRetry.plan(parentId, runHistory.retries(parentId),
                    api.siteMap().requestResponses().stream().map(HttpRequestResponse::request).filter(Objects::nonNull).toList(), api.scope()::isInScope);
            if (plan.targets().isEmpty()) {
                api.logging().logToOutput("[Recon Hound] No retry targets remain in the current in-scope site map."); return;
            }
            if (oastActiveRequests.get()) ensureCollaborator();
            boolean mutating = mutatingActiveRequests.get();
            var run = activeRuns.begin(ticket, mutating ? ScanProfile.ACTIVE_MUTATION : ScanProfile.ACTIVE_SAFE, plan.scope(), activeRequestLimits());
            run.parent(parentId);
            RunRetry.execute(plan, run, newTargetGateway(mutating), activeTestEngine, corpusFuzzEngine,
                    (finding, base) -> { if (activeRuns.isCurrent(ticket)) reportActiveFinding(finding, base); });
            api.logging().logToOutput("[Recon Hound] Retry run=" + run.id() + " parent=" + parentId + " unavailable probes=" + plan.unavailable());
        });
        return true;
    }

    /**
     * Opt-in corpus fuzz: replays the bundled {@code payloads/*.txt} corpus (see {@link PayloadLibrary})
     * against heuristically relevant parameters of every in-scope, parameterised site-map request, in
     * each requested encoding. Deliberately separate from {@link #runActiveTests()}'s small, curated
     * payload set — this corpus is large, so it's never fired implicitly.
     */
    void runCorpusFuzz(Set<PayloadEncoder.Encoding> encodings, int maxPerCategory) {
        if (!activeTestsEnabled.get()) {
            api.logging().logToOutput("[Recon Hound] Active tests are disabled; enable the opt-in checkbox first.");
            return;
        }
        if (oastActiveRequests.get()) ensureCollaborator();
        submitNativeActive(ticket -> {
            List<HttpRequest> targets = parameterizedTargets();

            boolean allowMutating = mutatingActiveRequests.get();
            ScanProfile profile = allowMutating ? ScanProfile.ACTIVE_MUTATION : ScanProfile.ACTIVE_SAFE;
            ScanRun run = activeRuns.begin(ticket, profile, ScopeSnapshot.forTargets(targets.stream().map(HttpRequest::url).toList()), activeRequestLimits());
            ActiveRequestGateway gateway = newTargetGateway(allowMutating);
            api.logging().logToOutput("[Recon Hound] Corpus-fuzzing " + targets.size()
                    + " in-scope parameterised request(s) (" + payloadLibrary.totalPayloads()
                    + " corpus payloads available, encodings=" + encodings + ", local category cap="
                    + maxPerCategory + ", global run cap=" + run.requestBudget().limit() + ")"
                    + (allowMutating ? " including non-safe methods." : " using safe methods only.")
                    + " Run=" + run.id());
            try {
                for (HttpRequest base : targets) {
                    if (!activeTestsEnabled.get()) {
                        run.cancel();
                        break;
                    }
                    if (run.requestBudget().exhausted()) break;
                    try {
                        for (HttpParameter parameter : base.parameters()) {
                            if (!activeTestsEnabled.get()) {
                                run.cancel();
                                break;
                            }
                            if (run.requestBudget().exhausted()) break;
                            if (parameter == null || parameter.name() == null || parameter.name().isBlank()) continue;
                            if ("COOKIE".equalsIgnoreCase(String.valueOf(parameter.type()))) continue;
                            for (ActiveTestEngine.ActiveFinding finding :
                                    corpusFuzzEngine.fuzz(base, parameter, encodings, maxPerCategory, run, gateway)) {
                                if (activeRuns.isCurrent(ticket)) reportActiveFinding(finding, base);
                            }
                        }
                    } catch (Exception e) {
                        api.logging().logToError("Corpus fuzz failed for " + base.url(), e);
                    }
                    publishStatus();
                }
            } finally {
                if (run.isActive()) run.complete();
            }
            api.logging().logToOutput("[Recon Hound] Corpus fuzz pass complete: "
                    + run.requestBudget().used() + "/" + run.requestBudget().limit()
                    + " request(s), status=" + run.status() + ", run=" + run.id()
                    + ". OOB results may arrive asynchronously.");
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
        if (!authLockoutActiveRequests.get()) {
            api.logging().logToOutput("[Recon Hound] JWT forgery is an authentication probe; enable the auth / lockout permission first.");
            return;
        }
        submitNativeActive(ticket -> {
            List<JwtTarget> targets = jwtTargets();
            api.logging().logToOutput("[Recon Hound] JWT alg:none test on " + targets.size() + " JWT-bearing request(s).");

            ScanRun run = activeRuns.begin(ticket, ScanProfile.ACTIVE_SAFE, ScopeSnapshot.forTargets(targets.stream().map(t -> t.request().url()).toList()), activeRequestLimits());
            ActiveRequestGateway gateway = newSafeTargetGateway();
            for (JwtTarget target : targets) {
                if (!activeTestsEnabled.get()) { run.cancel(); break; }
                if (run.requestBudget().exhausted()) break;
                try {
                    HttpRequest originalRequest = target.request();
                    NativeRequestStep baseline = JwtRequestPlanner.baseline(originalRequest);
                    ActiveRequestGateway.Result validResult = gateway.send(run, baseline.plan(), baseline.request());
                    if (!activeRuns.isCurrent(ticket)) return;
                    if (validResult.error() != null) {
                        api.logging().logToError("JWT baseline request failed for " + originalRequest.url(), validResult.error());
                        continue;
                    }
                    if (!validResult.dispatched()) continue;
                    HttpRequestResponse valid = validResult.response();
                    if (valid == null || valid.response() == null) continue;
                    int validStatus = valid.response().statusCode();
                    if (validStatus >= 400) continue;   // token not granting access here; nothing to bypass
                    int validLen = valid.response().bodyToString().length();

                    boolean reported = false;
                    for (NativeRequestStep variant : JwtRequestPlanner.noneVariants(target.request(), target.token())) {
                        if (run.requestBudget().exhausted()) break;
                        HttpRequest forgedReq = variant.request();
                        ActiveRequestGateway.Result forgedResult = gateway.send(run, variant.plan(), forgedReq);
                        if (!activeRuns.isCurrent(ticket)) return;
                        if (forgedResult.error() != null) {
                            api.logging().logToError("JWT alg:none request failed for " + target.request().url(), forgedResult.error());
                            continue;
                        }
                        if (!forgedResult.dispatched()) continue;
                        Thread.sleep(activeThrottleMillis.get());
                        HttpRequestResponse forged = forgedResult.response();
                        if (forged == null || forged.response() == null) continue;
                        int forgedStatus = forged.response().statusCode();
                        int forgedLen = forged.response().bodyToString().length();
                        boolean accepted = forgedStatus < 400 && forgedStatus == validStatus
                                && Math.abs(forgedLen - validLen) <= Math.max(64, validLen / 10);

                        FindingEvidence jwtEvidence = EvidenceCapture.helper("jwt-none", accepted ? VerificationState.REPRODUCED : VerificationState.REJECTED,
                                "Valid-token and unsigned-token status/length comparison. An accepted response alone does not prove a privileged authorization bypass.", originalRequest, validResult, forgedResult);
                        addActiveRow(accepted ? "HIGH" : "INFO", "JWT-none", "alg=none",
                                accepted ? "accepted" : "rejected",
                                "valid=" + validStatus + "/" + validLen + " forged=" + forgedStatus + "/" + forgedLen,
                                target.request().url(), jwtEvidence);

                        if (accepted && !reported) {
                            reported = true;
                            reporter.report("jwt-none\0" + target.request().url(),
                                    "JWT alg:none replay accepted",
                                    "<b>Server accepts an unsigned alg:none JWT</b><br>"
                                            + "URL: <code>" + escape(target.request().url()) + "</code><br><br>"
                                            + "A token re-encoded with <code>alg:none</code> and an empty signature was accepted "
                                            + "(status " + forgedStatus + ", matching the valid token's " + validStatus + "). "
                                            + "Confirm the response reflects authenticated privileges; status/length similarity alone is not proof of a signature-validation bypass."
                                            + evidenceDetail(jwtEvidence),
                                    "Reject <code>alg:none</code> server-side; pin the expected algorithm and always verify the signature.",
                                    target.request().url(), AuditIssueSeverity.HIGH, AuditIssueConfidence.FIRM,
                                    "Recon Hound replays JWT-bearing requests with an alg:none forgery to test signature validation.",
                                    "Confirm the forged token grants privileged access before reporting.",
                                    valid, forged);
                        }
                    }

                    // Weak-secret forgery: if the HMAC secret is a known weak value, mint a tampered token
                    // signed with it and confirm the server accepts a token it never issued.
                    if (!run.requestBudget().exhausted()) {
                        JwtRequestPlanner.WeakForgery weak = JwtRequestPlanner.weakSecret(target.request(), target.token());
                        if (weak != null) {
                            String secret = weak.secret();
                            HttpRequest forgedReq = weak.step().request();
                            ActiveRequestGateway.Result forgedResult = gateway.send(run, weak.step().plan(), forgedReq);
                            if (!activeRuns.isCurrent(ticket)) return;
                            if (forgedResult.error() != null) {
                                api.logging().logToError("JWT weak-secret request failed for " + target.request().url(), forgedResult.error());
                                continue;
                            }
                            if (!forgedResult.dispatched()) continue;
                            Thread.sleep(activeThrottleMillis.get());
                            HttpRequestResponse forged = forgedResult.response();
                            if (forged != null && forged.response() != null) {
                                int forgedStatus = forged.response().statusCode();
                                boolean accepted = forgedStatus < 400 && forgedStatus == validStatus;
                                FindingEvidence jwtEvidence = EvidenceCapture.helper("jwt-weak-secret", accepted ? VerificationState.REPRODUCED : VerificationState.REJECTED,
                                        "Offline weak-key match followed by a forged-token status comparison. Confirm actual privileges separately.", originalRequest, validResult, forgedResult);
                                addActiveRow(accepted ? "HIGH" : "INFO", "JWT-forge", "weak-secret",
                                        accepted ? "accepted" : "rejected",
                                        "weak key matched offline; status=" + forgedStatus, target.request().url(), jwtEvidence);
                                if (accepted) {
                                    reporter.report("jwt-forge\0" + target.request().url(),
                                            "JWT weak-secret replay accepted",
                                            "<b>Server accepts a token forged with a cracked secret</b><br>"
                                                    + "URL: <code>" + escape(target.request().url()) + "</code><br><br>"
                                                    + "The token's HMAC secret is the well-known value \"" + escape(secret) + "\". "
                                                    + "A token re-signed with it (and a tampered claim) was accepted (status "
                                                    + forgedStatus + "). An attacker can mint tokens with arbitrary claims "
                                                    + "(any user/role) if privileged authorization is established separately."
                                                    + evidenceDetail(jwtEvidence),
                                            "Rotate to a long, random signing key; never use guessable or boilerplate secrets.",
                                            target.request().url(), AuditIssueSeverity.HIGH, AuditIssueConfidence.FIRM,
                                            "Recon Hound cracks the HMAC secret offline, then replays a token re-signed with it to confirm forgery.",
                                            "Confirm the forged token grants privileges; matching status alone is insufficient.",
                                            valid, forged);
                                }
                            }
                        }
                    }
                    publishStatus();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    run.cancel();
                    return;
                } catch (Exception e) {
                    api.logging().logToError("JWT attack failed for " + target.request().url(), e);
                }
            }
            if (run.isActive()) run.complete();
            api.logging().logToOutput("[Recon Hound] JWT alg:none test complete (" + run.requestBudget().used()
                    + " request(s), run " + run.id() + ").");
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
        submitNativeActive(ticket -> {
            List<String> hosts = assetHosts.stream().sorted().toList();
            api.logging().logToOutput("[Recon Hound] Subdomain-takeover check on " + hosts.size() + " enumerated host(s).");
            ScanRun run = activeRuns.begin(ticket, ScanProfile.ACTIVE_SAFE, new ScopeSnapshot(Set.copyOf(hosts), Set.of()), activeRequestLimits());
            ActiveRequestGateway gateway = newSafeTargetGateway();
            try {
                for (String host : hosts) {
                    if (!activeTestsEnabled.get()) { run.cancel(); break; }
                    if (run.requestBudget().exhausted()) break;
                    for (String scheme : List.of("https://", "http://")) {
                        if (run.requestBudget().exhausted()) break;
                        String url = scheme + host + "/";
                        try {
                            NativeRequestStep step = TakeoverRequestPlanner.step(host, scheme);
                            ActiveRequestGateway.Result result = gateway.send(run, step.plan(), step.request());
                            if (!activeRuns.isCurrent(ticket)) return;
                            if (result.error() != null) {
                                api.logging().logToError("Takeover check failed for " + host, result.error());
                                continue;
                            }
                            if (!result.dispatched()) continue;
                            Thread.sleep(activeThrottleMillis.get());
                            HttpRequestResponse rr = result.response();
                            if (rr == null || rr.response() == null) continue;
                            String service = SubdomainTakeoverEngine.match(rr.response().bodyToString());
                            if (service == null) continue;

                            FindingEvidence takeoverEvidence = EvidenceCapture.helper("subdomain-takeover", VerificationState.CANDIDATE,
                                    "Unclaimed-resource fingerprint matched; DNS ownership and resource claimability are not established.", step.request(), result);
                            addActiveRow("HIGH", "Takeover", host, "fingerprint", service, url, takeoverEvidence);
                            reporter.report("takeover\0" + host + "\0" + service,
                                    "Potential subdomain takeover (" + service + ")",
                                    "<b>Dangling " + escape(service) + " resource</b><br>"
                                            + "Host: <code>" + escape(host) + "</code><br><br>"
                                            + "The host serves " + escape(service) + "'s 'unclaimed resource' page, which suggests a "
                                            + "dangling DNS record whose backend no longer exists. An attacker who claims that backend "
                                            + "can serve arbitrary content on this subdomain (phishing, cookie/session theft, CSP bypass)." + evidenceDetail(takeoverEvidence),
                                    "Remove the dangling DNS record, or (re)claim the " + escape(service) + " resource it points to.",
                                    url, AuditIssueSeverity.HIGH, AuditIssueConfidence.TENTATIVE,
                                    "Recon Hound fetches enumerated hosts and matches known subdomain-takeover fingerprints.",
                                    "Confirm the DNS points to a genuinely unclaimed resource before attempting a takeover (authorised only).",
                                    rr);
                            break;   // one scheme is enough for this host
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                            run.cancel();
                            return;
                        } catch (Exception e) {
                            api.logging().logToError("Takeover check failed for " + host, e);
                        }
                    }
                }
            } finally {
                if (run.isActive()) run.complete();
            }
            api.logging().logToOutput("[Recon Hound] Subdomain-takeover check complete (" + run.requestBudget().used()
                    + " request(s), run " + run.id() + ").");
            publishStatus();
        });
    }

    /** Sets the sqlmap binary path/name to invoke; blank means "sqlmap" resolved via PATH. */
    void setSqlmapPath(String path) { this.sqlmapClient = new SqlmapClient(path); }

    boolean sqlmapAvailable() { return sqlmapClient.isAvailable(); }

    /** Fail closed before queuing any external target producer, regardless of native grants. */
    void runSqlmap(String url, String method, String parameter, String body, String cookieHeader,
                    int level, int risk, String techniques, String extraArgs, long timeoutSeconds) {
        String reason = ExternalTargetEgress.blocked("sqlmap");
        api.logging().logToOutput("[Recon Hound] " + reason);
        addActiveRow("INFO", "sqlmap", "", "blocked", reason, "");
        publishStatus();
    }

    private static final Set<String> SAFE_METHODS = Set.of("GET", "HEAD", "OPTIONS");

    void runAccessControlTest(String sessionHeaders, boolean unauthenticated) {
        if (!activeTestsEnabled.get()) {
            api.logging().logToOutput("[Recon Hound] Active tests are disabled; enable the opt-in checkbox first.");
            return;
        }
        if (!authLockoutActiveRequests.get()) {
            api.logging().logToOutput("[Recon Hound] Alternate-identity replay is an authorization probe; enable the auth / lockout permission first.");
            return;
        }
        AccessControlEngine engine = new AccessControlEngine(sessionHeaders, unauthenticated);
        if (!engine.configured()) {
            api.logging().logToError("Access-control test needs alternate session headers or the unauthenticated option.");
            return;
        }
        submitNativeActive(ticket -> {
            List<HttpRequestResponse> targets = accessControlTargets();

            api.logging().logToOutput("[Recon Hound] Access-control replay of " + targets.size()
                    + " safe (GET/HEAD/OPTIONS) in-scope request(s) under the alternate identity.");
            ScanRun run = activeRuns.begin(ticket, ScanProfile.ACTIVE_SAFE, ScopeSnapshot.forTargets(targets.stream().map(t -> t.request().url()).toList()), activeRequestLimits());
            ActiveRequestGateway gateway = newSafeTargetGateway();

            for (HttpRequestResponse original : targets) {
                if (!activeTestsEnabled.get()) { run.cancel(); break; }
                if (run.requestBudget().exhausted()) break;
                try {
                    NativeRequestStep step = engine.plan(original.request());
                    HttpRequest replayRequest = step.request();
                    ActiveRequestGateway.Result replayResult = gateway.send(run, step.plan(), replayRequest);
                    if (!activeRuns.isCurrent(ticket)) return;
                    if (replayResult.error() != null) {
                        api.logging().logToError("Access-control replay failed for " + replayRequest.url(),
                                replayResult.error());
                        continue;
                    }
                    if (!replayResult.dispatched()) continue;
                    HttpRequestResponse replay = replayResult.response();
                    if (replay == null || replay.response() == null) continue;

                    AccessControlEngine.Result result = AccessControlEngine.classify(
                            original.response().statusCode(), original.response().bodyToString(),
                            replay.response().statusCode(), replay.response().bodyToString());

                    String url = original.request().url();
                    String dedupe = "ac\0" + url + "\0" + result.verdict();
                    if (!activeDedupe.add(dedupe)) continue;

                    VerificationState accessState = result.verdict() == AccessControlEngine.Verdict.BYPASSED
                            ? VerificationState.REPRODUCED : result.verdict() == AccessControlEngine.Verdict.PARTIAL
                            ? VerificationState.CANDIDATE : VerificationState.REJECTED;
                    FindingEvidence accessEvidence = EvidenceCapture.helper("access-control", accessState,
                            result.detail() + " Response comparison alone does not establish sensitive privilege exposure.", original.request(), replayResult)
                            .withOriginalResponse(EvidenceCapture.bytes(() -> original.response().toByteArray().getBytes()));
                    addActiveRow(result.severity(), "AccessControl", original.request().method(),
                            result.verdict().name().toLowerCase(Locale.ROOT), result.detail(), url, accessEvidence);

                    if (result.verdict() == AccessControlEngine.Verdict.BYPASSED
                            || result.verdict() == AccessControlEngine.Verdict.PARTIAL) {
                        AuditIssueSeverity severity = result.verdict() == AccessControlEngine.Verdict.BYPASSED
                                ? AuditIssueSeverity.HIGH : AuditIssueSeverity.MEDIUM;
                        reporter.report(
                                "ac-issue\0" + url + "\0" + result.verdict(),
                                "broken access control (" + result.verdict().name().toLowerCase(Locale.ROOT) + ")",
                                "<b>Access-control replay</b><br>" + escape(result.detail())
                                        + "<br>Identity: " + (unauthenticated ? "unauthenticated" : "alternate session") + evidenceDetail(accessEvidence),
                                "Enforce authorization server-side on every request; do not rely on the UI hiding functionality.",
                                url, severity,
                                result.verdict() == AccessControlEngine.Verdict.BYPASSED
                                        ? AuditIssueConfidence.FIRM : AuditIssueConfidence.TENTATIVE,
                                "Recon Hound replays privileged requests under a lower-privileged identity and compares responses.",
                                "Confirm the exposed data/action is genuinely sensitive; response size alone can mislead.",
                                original, replay);
                    }
                    publishStatus();
                } catch (Exception e) {
                    api.logging().logToError("Access-control replay failed", e);
                }
            }
            if (run.isActive()) run.complete();
            api.logging().logToOutput("[Recon Hound] Access-control test complete ("
                    + run.requestBudget().used() + " request(s), run " + run.id() + ").");
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
        assetWorker.submit(() -> {
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

    void pause() { setCrawlEnabled(false); publishStatus(); }
    void resume() { setCrawlEnabled(true); publishStatus(); }

    void reset() {
        stateGeneration.incrementAndGet();
        activeRuns.invalidate();
        domainRuns.invalidate();
        runHistory.clear();
        synchronized (crawlRuns) {
            crawlRuns.invalidate();
            crawlRun = null;
            previousCrawlUsage = 0;
            sentRequests.set(0);
        }
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
        SwingUtilities.invokeLater(() -> {
            findingModel.clear();
            discoveryModel.clear();
            parameterModel.clear();
            reflectionModel.clear();
            activeModel.clear();
            if (store != null) synchronized (stateWriteLock) { PersistedState.resetActiveEvidence(store); PersistedState.resetRunHistory(store); }
            assetModel.clear();
        });
        saveState();
        publishStatus();
    }

    void shutdown() {
        running.set(false);
        activeRuns.close();
        crawlRuns.close();
        domainRuns.close();
        // Stop the periodic saver first so it can't race the final blocking save on the PersistedObject.
        oobPoller.shutdownNow();
        saveStateBlocking();
        worker.shutdownNow();
        activeWorker.shutdownNow();
        llmWorker.shutdownNow();
        domainReconWorker.shutdownNow();
        assetWorker.shutdownNow();
    }

    /** Synchronous save for extension unload, when the async EDT task might not run in time. */
    private void saveStateBlocking() {
        if (store == null) return;
        try {
            java.util.concurrent.atomic.AtomicReference<StateSnapshot> captured = new java.util.concurrent.atomic.AtomicReference<>();
            Runnable task = () -> captured.set(snapshot(stateGeneration.get()));
            if (SwingUtilities.isEventDispatchThread()) task.run(); else SwingUtilities.invokeAndWait(task);
            writeSnapshot(captured.get());
        } catch (Exception e) { api.logging().logToError("Persisted-state save on shutdown failed", e); }
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
                + " | GF packs/rules/warnings: " + gfPatterns.packCount() + "/" + gfPatterns.ruleCount() + "/" + gfPatterns.diagnostics().size()
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

    ScanRun currentCrawlRun() {
        synchronized (crawlRuns) { return crawlRun; }
    }

    void crawlOne(QueueItem item) {
        URI current = item.uri();
        Set<String> redirectSeen = new HashSet<>();
        int hop = 0;
        ScanRun run;
        synchronized (crawlRuns) {
            if (!running.get() || !crawlEnabled.get()) return;
            if (crawlRun == null) {
                int remaining = Math.max(0, maxRequests.get() - previousCrawlUsage);
                crawlRun = crawlRuns.begin(crawlRuns.ticket(), ScanProfile.DISCOVERY, ScopeSnapshot.forTargetUrl(item.uri().toString()),
                        ScanRun.RequestLimits.globalOnly(remaining));
            }
            run = crawlRun;
        }
        ActiveRequestGateway gateway = newSafeTargetGateway();
        while (current != null && hop <= maxRedirects.get() && running.get()
                && crawlEnabled.get() && run.isActive()) {
            if (sentRequests.get() >= maxRequests.get()) return;
            if (!redirectSeen.add(current.toString())) return;

            NativeRequestStep step = crawlStep(current);
            ActiveRequestGateway.Result result = gateway.send(run, step.plan(), step.request());
            synchronized (crawlRuns) {
                if (run == crawlRun) sentRequests.set(previousCrawlUsage + run.requestBudget().used());
            }
            if (result.error() != null) {
                api.logging().logToError("Discovery request failed for " + current, result.error());
                return;
            }
            if (!result.dispatched()) return;
            api.logging().logToOutput("[Recon Hound] GET " + current + (hop > 0 ? " [redirect hop " + hop + "]" : ""));

            HttpRequestResponse rr = result.response();
            if (!run.isActive() || rr == null || !rr.hasResponse() || rr.response() == null) return;

            api.siteMap().add(rr);
            observationRun.set(run);
            try { processActivePair(rr, hop); } finally { observationRun.remove(); }

            HttpResponse response = rr.response();
            short code = response.statusCode();
            if (!followRedirects.get() || code < 300 || code >= 400) return;

            String location = response.headerValue("Location");
            URI next = discovery.redirectTarget(current, location);
            // Do not let auto-add-to-scope turn an unapproved redirect into an approved hop.
            if (next == null || !api.scope().isInScope(next.toString())) return;
            addDiscovered(next, item.rootOrigin(), "redirect " + code + " from " + current, false);
            current = next;
            hop++;
        }
    }

    private void submitNativeActive(Consumer<NativeRunRegistry.Ticket> work) {
        NativeRunRegistry.Ticket ticket = activeRuns.ticket();
        activeWorker.submit(() -> {
            if (!activeRuns.isCurrent(ticket)) return;
            try {
                work.accept(ticket);
            } catch (RuntimeException failure) {
                activeRuns.fail(ticket);
                throw failure;
            } finally {
                activeRuns.finish(ticket);
                saveState();
            }
        });
    }

    /** Shared safe-method gateway for native discovery and read-only replay paths. */
    private ActiveRequestGateway newSafeTargetGateway() {
        return newTargetGateway(false);
    }

    /**
     * Creates the single target-directed dispatch policy used by controller-owned active runs.
     * Non-safe methods require both method and state-changing permissions and are granted only after
     * the operator enables the explicit non-safe-method checkbox.
     */
    private ActiveRequestGateway newTargetGateway(boolean allowMutating) {
        return new ActiveRequestGateway(targetPolicy(allowMutating), targetTransport);
    }

    private RequestPolicy targetPolicy(boolean allowMutating) {
        EnumSet<RequestPolicy.Permission> permissions = EnumSet.noneOf(RequestPolicy.Permission.class);
        if (allowMutating) {
            permissions.add(RequestPolicy.Permission.UNSAFE_HTTP_METHOD);
            permissions.add(RequestPolicy.Permission.STATE_CHANGING);
        }
        if (oastActiveRequests.get()) permissions.add(RequestPolicy.Permission.OAST);
        if (persistentPayloadActiveRequests.get()) permissions.add(RequestPolicy.Permission.PERSISTENT_PAYLOAD);
        if (timeDelayActiveRequests.get()) permissions.add(RequestPolicy.Permission.TIME_DELAY);
        if (uploadActiveRequests.get()) permissions.add(RequestPolicy.Permission.UPLOAD);
        if (authLockoutActiveRequests.get()) {
            permissions.add(RequestPolicy.Permission.AUTHENTICATION_OR_LOCKOUT);
        }
        // The persistent-payload grant is independent of OAST. Destructive corpus entries are
        // still filtered before planning/execution, regardless of native risk grants.
        return new RequestPolicy(api.scope()::isInScope, permissions);
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
        scanDataExposure(request.url(), request, response, pair);
        scanSensitivePaths(request.url(), response, pair);
        scanFileUpload(request, response, pair);
        scanOAuth(request, pair);
        scanSaml(request, pair);
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
            addFindingRow(new ReconModel.FindingRow(
                    note.severity(), "hygiene", note.name(), "response", note.detail(), url));
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
                "Recon Hound passively inspects CORS, CSP, JWT, session-cookie attribute, and CSRF hygiene in in-scope traffic.",
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

    private void scanDataExposure(String url, HttpRequest request, HttpResponse response, HttpRequestResponse pair) {
        try {
            for (AuditIssue issue : dataExposureIssues(url, request, response, pair)) addToSiteMap(issue);
        } catch (Exception e) {
            api.logging().logToError("Data-exposure scan failed for " + url, e);
        }
    }

    /**
     * Builds excessive-data-exposure (response) and mass-assignment-candidate (request) issues from
     * JSON field names; adds a UI row only when a finding is newly built.
     */
    private List<AuditIssue> dataExposureIssues(String url, HttpRequest request, HttpResponse response, HttpRequestResponse pair) {
        List<AuditIssue> out = new ArrayList<>();
        String contentType = response.headerValue("Content-Type");
        boolean jsonish = contentType != null && contentType.toLowerCase(Locale.ROOT).contains("json");
        String body = response.bodyToString();
        if (jsonish || looksLikeJson(body)) {
            for (DataExposureEngine.Field field : DataExposureEngine.excessiveDataExposure(body)) {
                addIfPresent(out, buildDataExposureIssue(field, url, pair, true));
            }
        }
        if (request != null && isStateChangingMethod(request.method())) {
            String reqContentType = request.headerValue("Content-Type");
            boolean reqJsonish = reqContentType != null && reqContentType.toLowerCase(Locale.ROOT).contains("json");
            String reqBody = request.bodyToString();
            if (reqJsonish || looksLikeJson(reqBody)) {
                for (DataExposureEngine.Field field : DataExposureEngine.massAssignmentCandidates(reqBody)) {
                    addIfPresent(out, buildDataExposureIssue(field, url, pair, false));
                }
            }
        }
        return out;
    }

    private AuditIssue buildDataExposureIssue(DataExposureEngine.Field field, String url, HttpRequestResponse pair, boolean isExposure) {
        String kind = isExposure ? "excessive data exposure" : "mass-assignment candidate";
        AuditIssue issue = reporter.buildIfNew(
                (isExposure ? "exposure-issue\0" : "massassign-issue\0") + url + "\0" + field.path(),
                kind + " (" + field.key() + ")",
                "<b>" + (isExposure ? "Sensitive field present in an API response" : "Privileged field present in a request body") + "</b><br>"
                        + "Field: <code>" + escape(field.path()) + "</code><br>"
                        + "Value preview: <code>" + escape(field.valuePreview()) + "</code><br><br>"
                        + (isExposure
                            ? "This field name suggests sensitive data (credentials, PII, or payment/financial data) a "
                                    + "typical client response shouldn't need to include. Confirm whether the consuming "
                                    + "client actually needs this field, and remove it from the response if not."
                            : "This field name suggests a privileged/server-controlled attribute (role, verification "
                                    + "state, balance, etc.). If the server blindly binds request fields to its data "
                                    + "model, an attacker could set this directly. Confirm the server explicitly "
                                    + "allow-lists writable fields."),
                isExposure
                        ? "Remove unnecessary sensitive fields from API responses (use an explicit response DTO/serializer allow-list rather than returning the full internal model)."
                        : "Explicitly allow-list which client-supplied fields may be bound to the server-side model; never mass-bind/deserialize the whole request body onto a privileged entity.",
                url, isExposure ? AuditIssueSeverity.MEDIUM : AuditIssueSeverity.LOW, AuditIssueConfidence.TENTATIVE,
                "Recon Hound scans JSON " + (isExposure ? "responses" : "request bodies") + " for field names that suggest " + kind + ".",
                "This is a field-name heuristic, not a confirmed vulnerability; verify the field is actually attacker-reachable and unintended before treating it as a real finding.",
                pair);
        if (issue != null) {
            addActiveRow(isExposure ? "MEDIUM" : "LOW", isExposure ? "DataExposure" : "MassAssignment",
                    field.key(), "candidate", field.path() + " = " + field.valuePreview(), url);
        }
        return issue;
    }

    private static boolean looksLikeJson(String body) {
        if (body == null) return false;
        String trimmed = body.strip();
        return trimmed.startsWith("{") || trimmed.startsWith("[");
    }

    private static boolean isStateChangingMethod(String method) {
        if (method == null) return false;
        String upper = method.toUpperCase(Locale.ROOT);
        return upper.equals("POST") || upper.equals("PUT") || upper.equals("PATCH");
    }

    /** Passively inspects a request's URL parameters for OAuth 2.0 / OIDC authorization-flow weaknesses. */
    private void scanOAuth(HttpRequest request, HttpRequestResponse pair) {
        try {
            Map<String, String> urlParams = new LinkedHashMap<>();
            for (HttpParameter parameter : request.parameters()) {
                if (parameter.type() == HttpParameterType.URL) urlParams.put(parameter.name(), parameter.value());
            }
            if (urlParams.isEmpty()) return;
            for (OAuthEngine.Note note : OAuthEngine.analyze(request.url(), urlParams)) {
                addProtocolIssue("oauth", "OAuth/OIDC", note.severity(), note.name(), note.detail(), request.url(), pair,
                        "Recon Hound passively inspects OAuth/OIDC authorization requests for common flow weaknesses.",
                        "These are protocol-configuration leads; confirm against the actual authorization-server behaviour before reporting.");
            }
        } catch (Exception e) {
            api.logging().logToError("OAuth scan failed for " + request.url(), e);
        }
    }

    /** Passively decodes any SAMLRequest/SAMLResponse parameter and inspects it for message-level weaknesses. */
    private void scanSaml(HttpRequest request, HttpRequestResponse pair) {
        try {
            for (HttpParameter parameter : request.parameters()) {
                if (!SamlEngine.looksLikeSamlParam(parameter.name())) continue;
                for (SamlEngine.Note note : SamlEngine.analyze(parameter.value())) {
                    addProtocolIssue("saml", "SAML", note.severity(), note.name(), note.detail(), request.url(), pair,
                            "Recon Hound decodes SAMLRequest/SAMLResponse parameters and inspects them for signature/structure weaknesses.",
                            "These are structural signals from lightweight regex parsing, not a full XML-security audit; confirm manually.");
                }
            }
        } catch (Exception e) {
            api.logging().logToError("SAML scan failed for " + request.url(), e);
        }
    }

    /** Shared filer for the OAuth/SAML passive notes, which share the same simple name+detail+severity shape. */
    private void addProtocolIssue(String provider, String label, String severity, String name, String detail, String url,
                                  HttpRequestResponse pair, String background, String remediationBackground) {
        String dedupe = provider + "\0" + name + "\0" + url;
        if (!issueDedupe.add(dedupe)) return;
        addSyntheticFinding(severity, provider, name, "request", detail, url);
        reporter.report(provider + "-issue\0" + name + "\0" + url,
                name,
                "<b>" + escape(name) + "</b><br>" + escape(detail),
                "Review the " + label + " client/authorization-server configuration for this flow per the finding above.",
                url, IssueReporter.severity(severity), AuditIssueConfidence.TENTATIVE,
                background, remediationBackground, pair);
    }

    /**
     * Flags two path-based leads on a successful (2xx) response: a known debug/administration tool
     * path being reachable at all (Actuator, phpinfo, .git metadata, server-status, …), and a
     * privileged-looking path (admin/internal/backend/manage/console) as a BFLA candidate worth
     * confirming with the access-control replay feature. {@link AccessControlEngine} already
     * actively replays every safe-method endpoint under an alternate identity; this is the passive,
     * always-on discovery-time counterpart that surfaces which endpoints are worth that replay.
     */
    private void scanSensitivePaths(String url, HttpResponse response, HttpRequestResponse pair) {
        try {
            short code = response.statusCode();
            if (code < 200 || code >= 300) return;
            URI uri = safeUri(url);
            if (uri == null) return;

            if (InterestingResourceCatalog.looksLikeDebugTool(uri) && issueDedupe.add("debugpath\0" + url)) {
                addSyntheticFinding("MEDIUM", "exposure", "Debug/ops endpoint exposed", "response",
                        "Reachable debug/administration tooling path", url);
                reporter.report("debugpath-issue\0" + url,
                        "debug/ops endpoint exposed",
                        "<b>A known debug/administration tool path responded successfully</b><br>"
                                + "URL: <code>" + escape(url) + "</code><br><br>"
                                + "Framework debug endpoints, admin consoles, and management tooling (Actuator, "
                                + "phpinfo, .git metadata, server-status, etc.) commonly leak configuration, "
                                + "internal paths, credentials, or allow further compromise if left reachable.",
                        "Disable or restrict access to debug/administration tooling in production (network-level "
                                + "allow-listing, authentication, or removing it entirely).",
                        url, AuditIssueSeverity.MEDIUM, AuditIssueConfidence.FIRM,
                        "Recon Hound flags well-known debug/administration tool paths that returned a successful response.",
                        "Confirm the endpoint actually discloses sensitive information/functionality before reporting.",
                        pair);
            }

            if (InterestingResourceCatalog.looksLikePrivilegedPath(uri) && issueDedupe.add("bfla\0" + url)) {
                addSyntheticFinding("LOW", "authorization", "BFLA candidate", "response",
                        "Privileged-looking endpoint path", url);
                reporter.report("bfla-issue\0" + url,
                        "possible broken function-level authorization (BFLA) candidate",
                        "<b>Privileged-looking endpoint responded successfully</b><br>"
                                + "URL: <code>" + escape(url) + "</code><br><br>"
                                + "The path suggests admin/internal/management functionality. Verify that access "
                                + "control is actually enforced server-side for this endpoint and every HTTP method "
                                + "it accepts — the access-control replay feature (alternate-identity testing) can "
                                + "confirm this directly.",
                        "Enforce server-side authorization for every privileged endpoint and method; never rely on "
                                + "a path being \"hidden\" or unlinked from the UI.",
                        url, AuditIssueSeverity.LOW, AuditIssueConfidence.TENTATIVE,
                        "Recon Hound flags discovered paths whose names suggest admin/internal-only functionality.",
                        "A path name alone doesn't confirm broken access control; use the access-control replay feature to test it.",
                        pair);
            }
        } catch (Exception e) {
            api.logging().logToError("Sensitive-path scan failed for " + url, e);
        }
    }

    private void scanFileUpload(HttpRequest request, HttpResponse response, HttpRequestResponse pair) {
        try {
            String contentType = request.headerValue("Content-Type");
            if (!FileUploadEngine.looksLikeMultipartFileUpload(contentType)) return;
            String boundary = FileUploadEngine.extractBoundary(contentType);
            if (boundary == null) return;

            List<FileUploadEngine.UploadedFile> files =
                    FileUploadEngine.extractUploadedFiles(request.bodyToString(), boundary);
            if (files.isEmpty()) return;

            short code = response.statusCode();
            boolean accepted = code >= 200 && code < 300;
            String url = request.url();

            for (FileUploadEngine.UploadedFile file : files) {
                boolean dangerous = FileUploadEngine.isDangerousExtension(file.filename());
                boolean mimeMismatch = FileUploadEngine.mimeExtensionMismatch(file.filename(), file.declaredContentType());
                Optional<String> stored = accepted
                        ? FileUploadEngine.findStoredDangerousPath(response.bodyToString(), file.filename())
                        : Optional.empty();

                if (dangerous && accepted && issueDedupe.add("upload-dangerous\0" + url + "\0" + file.filename())) {
                    addSyntheticFinding(stored.isPresent() ? "HIGH" : "MEDIUM", "upload", "Executable file type accepted",
                            "response", "\"" + file.filename() + "\" (part \"" + file.partName() + "\")"
                                    + stored.map(p -> "; stored at " + p).orElse(""), url);
                    reporter.report("upload-dangerous-issue\0" + url + "\0" + file.filename(),
                            "Executable/script file type accepted by upload endpoint",
                            "<b>An upload with an executable/script extension was accepted</b><br>"
                                    + "URL: <code>" + escape(url) + "</code><br>"
                                    + "Filename: <code>" + escape(file.filename()) + "</code> (part \""
                                    + escape(file.partName()) + "\")<br>"
                                    + stored.map(p -> "Stored at: <code>" + escape(p) + "</code><br>").orElse("")
                                    + "<br>The server accepted a file whose extension (php/jsp/asp/exe/sh/...) is "
                                    + "commonly executed directly if reachable, rather than merely served as static content.",
                            "Validate uploads by content (not just extension/declared MIME type), store them outside "
                                    + "the webroot or with execution disabled, and serve them through a handler that "
                                    + "sets a safe Content-Disposition/Content-Type.",
                            url, stored.isPresent() ? AuditIssueSeverity.HIGH : AuditIssueSeverity.MEDIUM,
                            stored.isPresent() ? AuditIssueConfidence.FIRM : AuditIssueConfidence.TENTATIVE,
                            "Recon Hound inspects multipart file-upload requests for executable/script filename extensions.",
                            "Acceptance alone doesn't confirm the file is served as executable code; verify reachability.",
                            pair);
                }

                if (mimeMismatch && issueDedupe.add("upload-mime-mismatch\0" + url + "\0" + file.filename())) {
                    addSyntheticFinding("MEDIUM", "upload", "Upload content-type/extension mismatch", "request",
                            "\"" + file.filename() + "\" declared as " + file.declaredContentType(), url);
                    reporter.report("upload-mime-mismatch-issue\0" + url + "\0" + file.filename(),
                            "File upload declares a benign content-type for a dangerous extension",
                            "<b>An uploaded file's extension and declared Content-Type disagree</b><br>"
                                    + "Filename: <code>" + escape(file.filename()) + "</code><br>"
                                    + "Declared Content-Type: <code>" + escape(file.declaredContentType()) + "</code><br><br>"
                                    + "This is the shape of a classic content-type-only upload-filter bypass attempt: "
                                    + "the declared MIME type looks benign, but the extension is one many servers "
                                    + "execute directly regardless of what MIME type was declared alongside it.",
                            "Never trust the client-declared Content-Type; validate uploads by actual content/magic "
                                    + "bytes and enforce an extension allow-list server-side.",
                            url, AuditIssueSeverity.MEDIUM, AuditIssueConfidence.FIRM,
                            "Recon Hound compares an uploaded file's extension against its declared multipart Content-Type.",
                            "Flags the mismatch itself; whether the server actually executes the file must be confirmed separately.",
                            pair);
                }
            }
        } catch (Exception e) {
            api.logging().logToError("File-upload scan failed for " + request.url(), e);
        }
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

            if (ApiSurfaceEngine.hasGlobalSecurityRequirement(body)) {
                Set<String> authOptOuts = ApiSurfaceEngine.findAuthOptOutOperations(body, base);
                if (!authOptOuts.isEmpty()) {
                    String list = String.join("<br>", authOptOuts.stream().map(ReconController::escape).toList());
                    addSyntheticFinding("MEDIUM", "openapi", "Auth opt-out operations", "response",
                            authOptOuts.size() + " operation(s) explicitly disable the spec's default auth requirement", url);
                    reporter.report("openapi-auth-optout-issue\0" + url,
                            "OpenAPI spec declares operations that opt out of authentication",
                            "<b>" + authOptOuts.size() + " documented operation(s) explicitly set an empty security "
                                    + "requirement</b> (<code>\"security\": []</code>), opting out of the spec's default "
                                    + "authentication requirement.<br>Endpoints:<br>" + list + "<br><br>"
                                    + "Verify each of these genuinely needs to be unauthenticated; an accidental opt-out "
                                    + "is a common source of BOLA/IDOR.",
                            "Review every explicit security override and confirm it is intentional.",
                            url, AuditIssueSeverity.MEDIUM, AuditIssueConfidence.FIRM,
                            "Recon Hound parses OpenAPI specs for per-operation security overrides.",
                            "Flags explicit opt-outs only; endpoints silently inheriting the default aren't included.",
                            pair);
                }
            }
        } catch (Exception e) {
            api.logging().logToError("API spec ingestion failed for " + url, e);
        }
    }

    /** Five dependency-ordered evidence jobs with bounded local tools; no target transport or issue publisher. */
    Future<?> runEvidenceAgentJobs(EvidenceAgentJobs.Plan plan, Consumer<EvidenceAgentRunner.Event> onEvent,
                                   Consumer<EvidenceAgentRunner.Outcome> onDone) {
        return llmWorker.submit(() -> {
            EvidenceAgentRunner runner = new EvidenceAgentRunner((credential, system, prompt, maxTokens) ->
                    llmClient.complete(credential.provider(), credential.model(), credential.apiKey(), system, prompt, maxTokens));
            var outcome = runner.run(plan, event -> SwingUtilities.invokeLater(() -> onEvent.accept(event)),
                    () -> Thread.currentThread().isInterrupted(), usage -> emitAiFeed(AiFeed.Kind.AGENT_JOB,
                            usage.provider(), usage.model(), usage.outcome(), usage.input(), usage.output(),
                            usage.jobId() + " / call " + usage.call(), "Bounded evidence job; conclusions remain unverified."));
            SwingUtilities.invokeLater(() -> onDone.accept(outcome));
        });
    }

    /** One explicit, cancellable call per selected provider; no target transport or issue publisher. */
    Future<?> reviewEvidence(List<LlmClient.LlmCredential> credentials, AiAnalysis.Snapshot snapshot,
                             Consumer<AiAnalysis.ProviderReport> onReport, Runnable onDone) {
        List<LlmClient.LlmCredential> selected = List.copyOf(credentials);
        if (selected.isEmpty() || selected.size() > LlmProvider.values().length
                || selected.stream().map(LlmClient.LlmCredential::provider).distinct().count() != selected.size())
            throw new IllegalArgumentException("Select at most one model per provider.");
        return llmWorker.submit(() -> {
            try {
                for (var credential : selected) {
                    if (Thread.currentThread().isInterrupted()) break;
                    String raw = llmClient.complete(credential.provider(), credential.model(), credential.apiKey(),
                            AiAnalysis.SYSTEM, snapshot.prompt());
                    if (Thread.currentThread().isInterrupted()) break;
                    AiAnalysis.Report report = AiAnalysis.parse(raw, snapshot);
                    emitAiFeed(AiFeed.Kind.EVIDENCE_REVIEW, credential.provider(), credential.model(),
                            report.error() == null ? AiFeed.Outcome.OK : AiFeed.Outcome.ERROR,
                            AgentActivity.estimateTokens(AiAnalysis.SYSTEM + snapshot.prompt()),
                            AgentActivity.estimateTokens(raw), "Selected evidence review",
                            report.findings().size() + " unverified candidate(s); " + report.rejected() + " rejected entry/entries.");
                    SwingUtilities.invokeLater(() -> onReport.accept(
                            new AiAnalysis.ProviderReport(credential.provider(), credential.model(), report)));
                }
            } finally { SwingUtilities.invokeLater(onDone); }
        });
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
                        emitAiFeed(AiFeed.Kind.JS_REVIEW, credential.provider(), credential.model(),
                                transportError ? AiFeed.Outcome.ERROR : AiFeed.Outcome.OK,
                                AgentActivity.estimateTokens(body), 0, "JS review",
                                url + " — " + (transportError ? firstLine(analysis.error())
                                        : analysis.findings().size() + " finding(s)"));
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

    /** No credentials are resolved or work queued when remote target egress is unavailable. */
    void runPdcpScan(String uiKey, String teamId, List<String> targets, List<String> templates,
                     boolean recommended, java.util.function.Consumer<String> onProgress) {
        String reason = ExternalTargetEgress.blocked("PDCP scan creation");
        api.logging().logToOutput("[Recon Hound] " + reason);
        SwingUtilities.invokeLater(() -> onProgress.accept("[error] " + reason));
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
            emitAiFeed(AiFeed.Kind.NUCLEI_TEMPLATE, credential.provider(), credential.model(),
                    AiFeed.outcomeFor(finalResult), AgentActivity.estimateTokens(description),
                    AgentActivity.estimateTokens(finalResult), "Nuclei template", firstLine(description));
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
            long chainInTokens = AgentActivity.estimateTokens(inv.toString());
            if (analysis.chains().isEmpty()) {
                boolean chainErr = analysis.error() != null
                        && AiFeed.outcomeFor(analysis.error()) == AiFeed.Outcome.ERROR;
                emitAiFeed(AiFeed.Kind.CHAIN_ANALYSIS, credential.provider(), credential.model(),
                        chainErr ? AiFeed.Outcome.ERROR : AiFeed.Outcome.OK, chainInTokens, 0,
                        "Chain analysis: " + issues.size() + " finding(s)",
                        chainErr ? firstLine(analysis.error()) : "no chains identified");
                ui.accept(chainErr
                        ? "Chaining failed: " + firstLine(analysis.error())
                        : "No exploit chains identified across " + issues.size() + " finding(s).");
                return;
            }
            int filed = 0;
            for (LlmClient.LlmChain chain : analysis.chains()) {
                if (fileChainIssue(chain, issues)) filed++;
            }
            emitAiFeed(AiFeed.Kind.CHAIN_ANALYSIS, credential.provider(), credential.model(), AiFeed.Outcome.OK,
                    chainInTokens, 0, "Chain analysis: " + issues.size() + " finding(s)", filed + " chain(s) filed");
            String summary = "Chaining complete: " + filed + " exploit chain(s) filed as native Burp issues from "
                    + issues.size() + " finding(s). See Burp Issues / the Active tab.";
            api.logging().logToOutput("[Recon Hound] " + summary);
            ui.accept(summary);
            publishStatus();
        });
    }

    /**
     * Opt-in multi-agent run over the in-scope finding inventory. Runs the configured team — recon
     * prioritises, the exploit drafter reasons a PoC on paper, a different-provider verifier attacks
     * it, and the elected leader synthesises and proposes next steps. Every proposed step is classified
     * by {@link ActionGate}: passive/drafting is reported, anything that would touch the target is
     * filed as a human-approval escalation. This method sends NO target traffic — only LLM calls.
     */
    void runAgentTeam(List<AgentTeam.AgentSpec> specs, int maxFindings,
                      java.util.function.Consumer<AgentActivity.RunEntry> onRound,
                      java.util.function.Consumer<AgentActivity.RunSummary> onDone) {
        java.util.function.Consumer<AgentActivity.RunEntry> round =
                e -> SwingUtilities.invokeLater(() -> onRound.accept(e));
        java.util.function.Consumer<AgentActivity.RunSummary> done =
                s -> SwingUtilities.invokeLater(() -> onDone.accept(s));
        if (specs == null || specs.isEmpty()) {
            done.accept(new AgentActivity.RunSummary("HOLD",
                    "[error] No LLM provider enabled — check a provider's box and set its key.", List.of(), ""));
            return;
        }
        AgentTeam.Plan plan = AgentTeam.plan(specs);
        if (plan.leader() == null) {
            done.accept(new AgentActivity.RunSummary("HOLD", "[error] No agent could be elected leader.", List.of(), ""));
            return;
        }

        llmWorker.submit(() -> {
            List<AuditIssue> issues = api.siteMap().issues().stream()
                    .filter(Objects::nonNull)
                    .filter(i -> { try { return api.scope().isInScope(i.baseUrl()); } catch (Exception e) { return false; } })
                    .filter(i -> !i.name().startsWith("Recon Hound: Chain:"))
                    .collect(java.util.stream.Collectors.toMap(
                            i -> i.name() + "\0" + i.baseUrl(), i -> i, (a, b) -> a, LinkedHashMap::new))
                    .values().stream()
                    .sorted(java.util.Comparator.comparingInt(ReconController::severityRank))
                    .limit(Math.max(1, maxFindings))
                    .toList();
            if (issues.isEmpty()) {
                done.accept(new AgentActivity.RunSummary("HOLD",
                        "[no in-scope findings — run a crawl/scan first]", List.of(), ""));
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
            String inventory = inv.toString();

            List<AgentOrchestrator.RoundResult> rounds = new ArrayList<>();
            List<AgentActivity.RunEntry> entries = new ArrayList<>();

            for (AgentTeam.AgentSpec spec : AgentOrchestrator.workerOrder(plan)) {
                String system = AgentOrchestrator.systemPromptFor(spec.role());
                String user = AgentOrchestrator.userPromptFor(spec.role(), inventory, rounds);
                String out = llmClient.complete(spec.provider(), spec.resolvedModel(), spec.apiKey(), system, user);
                rounds.add(new AgentOrchestrator.RoundResult(spec.role(), spec.provider(), out));
                AgentActivity.RunEntry entry = new AgentActivity.RunEntry(spec.role(), spec.provider(),
                        spec.resolvedModel(), agentRoundStatus(out),
                        AgentActivity.estimateTokens(system + "\n" + user), AgentActivity.estimateTokens(out),
                        firstLine(out));
                entries.add(entry);
                round.accept(entry);
                emitAiFeed(AiFeed.Kind.AGENT_ROUND, spec.provider(), spec.resolvedModel(),
                        AiFeed.outcomeFor(out), entry.estInputTokens(), entry.estOutputTokens(),
                        spec.role().title() + " round", entry.summary());
            }

            AgentTeam.AgentSpec leader = plan.leader();
            String leaderSystem = AgentOrchestrator.systemPromptFor(AgentRole.LEADER);
            String leaderUser = AgentOrchestrator.userPromptFor(AgentRole.LEADER, inventory, rounds);
            String leaderOut = llmClient.complete(leader.provider(), leader.resolvedModel(), leader.apiKey(),
                    leaderSystem, leaderUser);
            rounds.add(new AgentOrchestrator.RoundResult(AgentRole.LEADER, leader.provider(), leaderOut));
            AgentActivity.RunEntry leaderEntry = new AgentActivity.RunEntry(AgentRole.LEADER, leader.provider(),
                    leader.resolvedModel(), agentRoundStatus(leaderOut),
                    AgentActivity.estimateTokens(leaderSystem + "\n" + leaderUser), AgentActivity.estimateTokens(leaderOut),
                    firstLine(leaderOut));
            entries.add(leaderEntry);
            round.accept(leaderEntry);
            emitAiFeed(AiFeed.Kind.AGENT_ROUND, leader.provider(), leader.resolvedModel(),
                    AiFeed.outcomeFor(leaderOut), leaderEntry.estInputTokens(), leaderEntry.estOutputTokens(),
                    AgentRole.LEADER.title() + " round", leaderEntry.summary());

            AgentOrchestrator.Outcome outcome = AgentOrchestrator.decide(rounds, leaderOut);
            String synthesis = outcome.leaderSynthesis().isBlank()
                    ? "(no synthesis produced — the leader request may have failed; see the round table)"
                    : outcome.leaderSynthesis();
            api.logging().logToOutput("[Recon Hound] Agent team run complete: " + outcome.decision()
                    + ", " + outcome.escalations().size() + " escalation(s).");
            AiFeed.Outcome decisionOutcome = switch (outcome.decision()) {
                case PROCEED -> AiFeed.Outcome.OK;
                case ESCALATE, HOLD -> AiFeed.Outcome.HELD;
            };
            // The gate decision is computed locally, not by an LLM call, so it carries no provider/model
            // (AiFeed.aggregate must not count it as a provider call).
            emitAiFeed(AiFeed.Kind.GATE_DECISION, null, null, decisionOutcome,
                    0, 0, "Leader decision: " + outcome.decision(), firstLine(synthesis));
            for (String esc : outcome.escalations()) {
                emitAiFeed(AiFeed.Kind.ESCALATION, null, null, AiFeed.Outcome.HELD, 0, 0,
                        "Human approval required", esc);
            }
            done.accept(new AgentActivity.RunSummary(outcome.decision().name(), synthesis,
                    outcome.escalations(), AgentActivity.formatUsage(entries)));
            publishStatus();
        });
    }

    /** Registers the UI's AI-feed listener; events (and it) are always delivered on the EDT. */
    void setAiFeedListener(java.util.function.Consumer<AiFeed.Event> listener) { this.aiFeedListener = listener; }

    /** Snapshot of the whole AI feed (oldest-first). Call on the EDT — the store is EDT-confined. */
    List<AiFeed.Event> aiFeedSnapshot() { return aiFeed.snapshot(); }

    /** Clears the AI feed. Call on the EDT. */
    void clearAiFeed() { aiFeed.clear(); }

    /**
     * Records an AI-activity event into the in-memory feed and notifies the UI. Both the store write
     * and the listener call happen on the EDT, so the store stays single-thread-confined even though
     * callers run on {@link #llmWorker} / {@link #activeWorker} background threads.
     */
    private void emitAiFeed(AiFeed.Kind kind, LlmProvider provider, String model, AiFeed.Outcome outcome,
                            long estIn, long estOut, String title, String detail) {
        SwingUtilities.invokeLater(() -> {
            AiFeed.Event e = aiFeed.record(kind, provider, model, outcome, estIn, estOut, title, detail);
            java.util.function.Consumer<AiFeed.Event> l = aiFeedListener;
            if (l != null) l.accept(e);
        });
    }

    /** Round status for the activity table: an LlmClient failure sentinel reads as "error", else "ok". */
    private static String agentRoundStatus(String output) {
        if (output == null) return "error";
        return (output.startsWith("[error]") || output.startsWith("[HTTP ") || output.startsWith("[warning]"))
                ? "error" : "ok";
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
            int batchSize = batch.size();
            for (LlmClient.LlmCredential credential : credentials) {
                llmWorker.submit(() -> {
                    LlmClient.TriageBatchResult r;
                    try {
                        r = llmClient.triage(credential, batchPrompt);
                    } catch (Exception e) {
                        r = new LlmClient.TriageBatchResult(List.of(), "[error] " + e.getMessage());
                    }
                    results.add(r);
                    boolean ok = !r.verdicts().isEmpty();
                    emitAiFeed(AiFeed.Kind.TRIAGE, credential.provider(), credential.model(),
                            ok ? AiFeed.Outcome.OK : AiFeed.Outcome.ERROR,
                            AgentActivity.estimateTokens(batchPrompt), 0,
                            "Triage: " + batchSize + " finding(s)",
                            ok ? r.verdicts().size() + " verdict(s)" : firstLine(r.error()));
                    latch.countDown();
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
        if (!activeTestsEnabled.get()) {
            api.logging().logToOutput("[Recon Hound] Active tests are disabled; enable the opt-in checkbox first.");
            return;
        }
        if (!mutatingActiveRequests.get()) {
            api.logging().logToOutput("[Recon Hound] GraphQL introspection uses POST; enable the non-safe-method opt-in first.");
            return;
        }
        submitNativeActive(ticket -> {
            String target = url == null ? "" : url.trim();
            if (!target.startsWith("http")) { api.logging().logToError("Invalid GraphQL URL: " + target); return; }
            if (!api.scope().isInScope(target)) { api.logging().logToError("GraphQL target not in scope: " + target); return; }
            ScanRun run = activeRuns.begin(ticket, ScanProfile.ACTIVE_MUTATION, ScopeSnapshot.forTargetUrl(target),
                    activeRequestLimits(1));
            ActiveRequestGateway gateway = newTargetGateway(true);
            try {
                NativeRequestStep step = GraphQlRequestPlanner.introspection(httpRequestFromUrl(target));
                ActiveRequestGateway.Result introspectionResult = gqlPost(step, run, gateway);
                if (!activeRuns.isCurrent(ticket)) return;
                HttpRequestResponse rr = introspectionResult.response();
                if (rr == null || rr.response() == null) return;
                ApiSurfaceEngine.IntrospectionDetail detail = ApiSurfaceEngine.analyzeIntrospection(rr.response().bodyToString());
                String summary = ApiSurfaceEngine.describe(detail);
                boolean enabled = detail.enabled();
                FindingEvidence introspectionEvidence = EvidenceCapture.helper("graphql-introspection",
                        enabled ? VerificationState.REPRODUCED : VerificationState.REJECTED,
                        summary + " Schema visibility alone is not proof of authorization impact.", step.request(), introspectionResult);
                addActiveRow(enabled ? "MEDIUM" : "INFO", "GraphQL", "introspection",
                        enabled ? "enabled" : "checked", summary, target, introspectionEvidence);
                if (enabled && rr.hasResponse()) {
                    reporter.report(
                            "graphql-introspection-issue\0" + target,
                            "GraphQL introspection enabled",
                            "<b>GraphQL introspection is enabled</b><br>" + escape(summary) + evidenceDetail(introspectionEvidence),
                            "Disable introspection in production to reduce schema disclosure.",
                            target, AuditIssueSeverity.LOW, AuditIssueConfidence.FIRM,
                            "Recon Hound queried the GraphQL introspection endpoint on request.",
                            "Introspection disclosure is informational to low severity depending on exposure.",
                            rr);
                    if (!detail.sensitiveNames().isEmpty()) {
                        reporter.report(
                                "graphql-sensitive-schema-issue\0" + target,
                                "GraphQL introspection exposes sensitive-sounding fields",
                                "<b>Sensitive-sounding fields/mutations discoverable via introspection</b><br>"
                                        + escape(String.join(", ", detail.sensitiveNames())) + "<br><br>"
                                        + "Introspection lets an attacker enumerate exactly which dangerous mutations/fields "
                                        + "exist before ever calling them, focusing follow-up testing (BOLA, privilege "
                                        + "escalation, mass assignment).<br>Field-name heuristic: candidate only; no resolver authorization test was performed."
                                        + "<br>Source evidence ID: <code>" + escape(introspectionEvidence.id()) + "</code>",
                                "Disable introspection in production; regardless, enforce authorization on every "
                                        + "resolver independent of schema visibility.",
                                target, AuditIssueSeverity.MEDIUM, AuditIssueConfidence.FIRM,
                                "Recon Hound scans the introspected schema's field/type names for sensitive-sounding keywords.",
                                "Name-based heuristic; confirm each flagged field's actual authorization requirement.",
                                rr);
                    }
                }
                api.logging().logToOutput("[Recon Hound] GraphQL introspection on " + target + ": " + summary
                        + " (run " + run.id() + ")");
            } catch (Exception e) {
                run.fail(e.getMessage());
                api.logging().logToError("GraphQL introspection failed for " + target, e);
            } finally {
                if (run.isActive()) run.complete();
            }
        });
    }

    /** Active GraphQL fuzzing beyond introspection: field-suggestion leakage, alias amplification, batching. */
    void fuzzGraphql(String url) {
        if (!activeTestsEnabled.get()) {
            api.logging().logToOutput("[Recon Hound] Active tests are disabled; enable the opt-in checkbox first.");
            return;
        }
        if (!mutatingActiveRequests.get()) {
            api.logging().logToOutput("[Recon Hound] GraphQL fuzzing uses POST; enable the non-safe-method opt-in first.");
            return;
        }
        submitNativeActive(ticket -> {
            String target = url == null ? "" : url.trim();
            if (!target.startsWith("http")) { api.logging().logToError("Invalid GraphQL URL: " + target); return; }
            if (!api.scope().isInScope(target)) { api.logging().logToError("GraphQL target not in scope: " + target); return; }
            ScanRun run = activeRuns.begin(ticket, ScanProfile.ACTIVE_MUTATION, ScopeSnapshot.forTargetUrl(target),
                    activeRequestLimits(3));
            ActiveRequestGateway gateway = newTargetGateway(true);
            try {
                List<NativeRequestStep> steps = GraphQlRequestPlanner.fuzz(httpRequestFromUrl(target));
                ActiveRequestGateway.Result suggestResult = gqlPost(steps.get(0), run, gateway);
                if (!activeRuns.isCurrent(ticket)) return;
                HttpRequestResponse suggest = suggestResult.response();
                if (bodyOf(suggest) != null && GraphQlFuzzEngine.hasFieldSuggestions(bodyOf(suggest))) {
                    FindingEvidence suggestEvidence = EvidenceCapture.helper("graphql-field-suggestions", VerificationState.REPRODUCED,
                            "The recorded response exhibited the tested GraphQL feature; exploit impact remains unverified.", steps.get(0).request(), suggestResult);
                    addActiveRow("LOW", "GraphQL", "field-suggestions", "enabled", "'Did you mean' leaks schema", target,
                            suggestEvidence);
                    reporter.report("gql-suggest\0" + target, "GraphQL field suggestions enabled",
                            "<b>GraphQL field suggestions are enabled</b><br>Even with introspection disabled, the server "
                                    + "returns 'Did you mean' hints for invalid fields, leaking schema details that help an attacker map the API." + evidenceDetail(suggestEvidence),
                            "Disable did-you-mean/field suggestions in production.",
                            target, AuditIssueSeverity.LOW, AuditIssueConfidence.FIRM,
                            "Recon Hound probes GraphQL with an invalid field to detect suggestion leakage.",
                            "Schema disclosure via suggestions is low severity but aids further attacks.", suggest);
                }

                int aliases = GraphQlRequestPlanner.ALIASES;
                ActiveRequestGateway.Result aliasResult = gqlPost(steps.get(1), run, gateway);
                if (!activeRuns.isCurrent(ticket)) return;
                HttpRequestResponse alias = aliasResult.response();
                if (bodyOf(alias) != null && GraphQlFuzzEngine.aliasingProcessed(bodyOf(alias), aliases)) {
                    FindingEvidence aliasEvidence = EvidenceCapture.helper("graphql-alias-amplification", VerificationState.REPRODUCED,
                            "The recorded response exhibited the tested GraphQL feature; exploit impact remains unverified.", steps.get(1).request(), aliasResult);
                    addActiveRow("MEDIUM", "GraphQL", "alias-amplification", "enabled", aliases + " aliases in one request", target,
                            aliasEvidence);
                    reporter.report("gql-alias\0" + target, "GraphQL alias-based amplification",
                            "<b>GraphQL processes many field aliases per request</b><br>" + aliases + " aliases of a field were "
                                    + "processed in a single request. Aliasing amplifies work/attempts (brute-forcing a login mutation, "
                                    + "resource exhaustion) while sending one request. Impact on sensitive operations is unverified." + evidenceDetail(aliasEvidence),
                            "Enforce query cost/complexity limits and cap aliases per request.",
                            target, AuditIssueSeverity.MEDIUM, AuditIssueConfidence.FIRM,
                            "Recon Hound sends an alias-amplified query to test cost controls.",
                            "Confirm the amplification is usable against a sensitive operation.", alias);
                }

                ActiveRequestGateway.Result batchResult = gqlPost(steps.get(2), run, gateway);
                if (!activeRuns.isCurrent(ticket)) return;
                HttpRequestResponse batch = batchResult.response();
                if (bodyOf(batch) != null && GraphQlFuzzEngine.batchingProcessed(bodyOf(batch))) {
                    FindingEvidence batchEvidence = EvidenceCapture.helper("graphql-query-batching", VerificationState.REPRODUCED,
                            "The recorded response exhibited the tested GraphQL feature; exploit impact remains unverified.", steps.get(2).request(), batchResult);
                    addActiveRow("MEDIUM", "GraphQL", "query-batching", "enabled", "array of operations processed", target,
                            batchEvidence);
                    reporter.report("gql-batch\0" + target, "GraphQL query batching enabled",
                            "<b>GraphQL query batching is enabled</b><br>The endpoint processed a JSON array of operations in a "
                                    + "single request. Impact on rate limits and sensitive operations is unverified." + evidenceDetail(batchEvidence),
                            "Disable array-based query batching, or apply per-operation rate limiting and cost analysis.",
                            target, AuditIssueSeverity.MEDIUM, AuditIssueConfidence.FIRM,
                            "Recon Hound sends a batched operation array to test whether batching is enabled.",
                            "Confirm batching is usable against a sensitive operation.", batch);
                }
                api.logging().logToOutput("[Recon Hound] GraphQL fuzzing complete for " + target
                        + " (" + run.requestBudget().used() + " request(s), run " + run.id() + ")");
            } catch (Exception e) {
                run.fail(e.getMessage());
                api.logging().logToError("GraphQL fuzzing failed for " + target, e);
            } finally {
                if (run.isActive()) run.complete();
            }
            publishStatus();
        });
    }

    private ActiveRequestGateway.Result gqlPost(NativeRequestStep step, ScanRun run, ActiveRequestGateway gateway) {
        ActiveRequestGateway.Result result = gateway.send(run, step.plan(), step.request());
        if (result.error() != null) {
            api.logging().logToError("GraphQL request failed", result.error());
        }
        return result;
    }

    enum PreviewAction { PARAMETERS, GRAPHQL_INTROSPECTION, GRAPHQL_FUZZ }

    /** Preview works with active sending disabled. No tickets, transport or Collaborator access. */
    String previewRequests(String url, PreviewAction action) {
        try {
            String target = url == null ? "" : url.strip();
            URI uri = URI.create(target);
            if (uri.getHost() == null || !("https".equalsIgnoreCase(uri.getScheme()) || "http".equalsIgnoreCase(uri.getScheme())))
                return "Choose an absolute HTTP(S) URL. No requests sent.";
            HttpRequest base = httpRequestFromUrl(target);
            Iterable<NativeRequestStep> steps = switch (action) {
                case PARAMETERS -> parameterDiscovery.plan(base);
                case GRAPHQL_INTROSPECTION -> List.of(GraphQlRequestPlanner.introspection(base));
                case GRAPHQL_FUZZ -> GraphQlRequestPlanner.fuzz(base);
            };
            int cap = switch (action) { case PARAMETERS -> Integer.MAX_VALUE; case GRAPHQL_INTROSPECTION -> 1; case GRAPHQL_FUZZ -> 3; };
            ScanRun run = ScanRun.begin(ScanProfile.ACTIVE_SAFE, ScopeSnapshot.forTargetUrl(target), activeRequestLimits(cap));
            RequestPolicy policy = action == PreviewAction.PARAMETERS ? RequestPolicy.safeDefault(api.scope()::isInScope)
                    : targetPolicy(mutatingActiveRequests.get());
            return RequestPreview.inspect(run, policy, steps).render();
        } catch (RuntimeException e) {
            return "Could not prepare this request preview. No requests sent.";
        }
    }

    String previewActiveTests(String probeFilter) {
        return previewSafely(() -> {
            Iterable<NativeRequestStep> steps = () -> parameterizedTargets().stream()
                    .flatMap(base -> stream(activeTestEngine.plan(base, probeFilter))).iterator();
            String report = inspectActivePreview(steps, targetPolicy(mutatingActiveRequests.get()));
            return probeFilter == null || probeFilter.isBlank() ? report
                    : "Filtered preview: counts cover the selected probe alone. Running active tests still executes the full pass.\n\n" + report;
        });
    }

    String previewCorpusFuzz(Set<PayloadEncoder.Encoding> encodings, int maxPerCategory) {
        return previewCorpusFuzz(encodings, maxPerCategory, null);
    }

    String previewCorpusFuzz(Set<PayloadEncoder.Encoding> encodings, int maxPerCategory, String categoryFilter) {
        return previewSafely(() -> {
            if (encodings == null || encodings.isEmpty() || maxPerCategory <= 0) return "Choose encodings and a positive category cap. No requests sent.";
            Iterable<NativeRequestStep> steps = () -> parameterizedTargets().stream().flatMap(base -> base.parameters().stream()
                    .filter(p -> p != null && p.name() != null && !p.name().isBlank() && p.type() != burp.api.montoya.http.message.params.HttpParameterType.COOKIE)
                    .flatMap(p -> stream(corpusFuzzEngine.plan(base, p, encodings, maxPerCategory, categoryFilter)))).iterator();
            String report = inspectActivePreview(steps, targetPolicy(mutatingActiveRequests.get()));
            return categoryFilter == null ? report : "Filtered preview: counts cover the selected category alone. Running corpus fuzz still uses all relevant categories.\n\n" + report;
        });
    }

    String previewJwtAttacks() {
        return previewSafely(() -> {
            Iterable<NativeRequestStep> steps = () -> jwtTargets().stream()
                    .flatMap(target -> stream(JwtRequestPlanner.plan(target.request(), target.token()))).iterator();
            return inspectActivePreview(steps, targetPolicy(false));
        });
    }

    String previewTakeover() {
        return previewSafely(() -> inspectActivePreview(() -> assetHosts.stream().sorted()
                .flatMap(host -> stream(TakeoverRequestPlanner.plan(host))).iterator(), targetPolicy(false)));
    }

    String previewAccessControl(String headers, boolean unauthenticated) {
        return previewSafely(() -> {
            AccessControlEngine engine = new AccessControlEngine(headers, unauthenticated);
            if (!engine.configured()) return "Choose an alternate identity or unauthenticated replay. No requests sent.";
            return inspectActivePreview(() -> accessControlTargets().stream().map(rr -> engine.plan(rr.request())).iterator(), targetPolicy(false));
        });
    }

    private NativeRequestStep crawlStep(URI uri) {
        return new NativeRequestRecipe(() -> buildAuthenticatedGet(uri), "discovery-crawl", Set.of(), NativeRequestStep.Mutation.CRAWL_GET,
                NativeRequestStep.Condition.ALWAYS, "origin authentication values hidden", false).build();
    }

    String previewCrawl(String seedText) {
        return previewSafely(() -> {
            ScanRun run;
            synchronized (crawlRuns) {
                run = crawlRun == null ? ScanRun.begin(ScanProfile.DISCOVERY, ScopeSnapshot.empty(),
                        ScanRun.RequestLimits.globalOnly(Math.max(0, maxRequests.get() - previousCrawlUsage))) : crawlRun.previewCopy();
            }
            List<URI> queued = queue.stream().map(QueueItem::uri).toList();
            Iterable<NativeRequestStep> steps = () -> java.util.stream.Stream.concat(
                    queued.stream(), Arrays.stream((seedText == null ? "" : seedText).split("\\R"))
                            .map(String::trim).filter(line -> !line.isEmpty() && !line.startsWith("#")).map(URI::create))
                    .distinct().flatMap(uri -> {
                        Object rootAdmission = new Object();
                        java.util.stream.Stream<NativeRequestStep> first = java.util.stream.Stream.of(crawlStep(uri).withConstraints(
                                new NativeRequestStep.Constraints(null, 0, 1, null, rootAdmission)));
                        java.util.stream.Stream<NativeRequestStep> redirects = java.util.stream.IntStream.range(0, followRedirects.get() ? maxRedirects.get() : 0)
                                .mapToObj(i -> new NativeRequestStep(null, null, NativeRequestStep.Mutation.CRAWL_REDIRECT, List.of(),
                                        NativeRequestStep.Condition.REDIRECT_RESPONSE, "possible hop " + (i + 1) + "; current scope required",
                                        RequestPolicy.PlannedRequest.safe("GET", uri.toString(), "discovery-crawl"))
                                        .withConstraints(new NativeRequestStep.Constraints(null, 0, 1, rootAdmission, null)));
                        return java.util.stream.Stream.concat(first, redirects);
                    }).iterator();
            return RequestPreview.inspect(run, RequestPolicy.safeDefault(api.scope()::isInScope), steps).render();
        });
    }

    private String inspectActivePreview(Iterable<NativeRequestStep> steps, RequestPolicy policy) {
        ScanRun run = ScanRun.begin(ScanProfile.ACTIVE_SAFE, ScopeSnapshot.empty(), activeRequestLimits());
        return RequestPreview.inspect(run, policy, steps).render();
    }

    private static java.util.stream.Stream<NativeRequestStep> stream(Iterable<NativeRequestStep> steps) {
        return java.util.stream.StreamSupport.stream(steps.spliterator(), false);
    }

    private static String previewSafely(java.util.function.Supplier<String> preview) {
        try { return preview.get(); }
        catch (RuntimeException e) { return "Could not prepare this request preview. No requests sent."; }
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
            String dedupe = "hound\0" + observationRunId() + "\0" + finding.rule().id() + "\0" + finding.value() + "\0" + url;
            if (!issueDedupe.add(dedupe)) continue;

            addFindingRow(new ReconModel.FindingRow(
                    finding.rule().severity().name(), finding.rule().provider(), finding.rule().name(),
                    location, RegexHound.redact(finding.value()), url
            ));

            addAuditIssue(finding, pair);
        }

        if (scanGfPatterns.get()) {
            for (GfPatternLoader.GfMatch match : gfPatterns.scan(text)) {
                if (!includeGfMatch(match)) continue;
                String dedupe = "gf\0" + observationRunId() + "\0" + match.pack() + "\0" + match.ruleId() + "\0" + match.value() + "\0" + url;
                if (!issueDedupe.add(dedupe)) continue;
                addSyntheticFinding(match.severity(), "gf:" + match.provider(), "gf:" + match.ruleId(),
                        location, match.displayValue(), match.displaySourceUrl(url));
                addToSiteMap(buildGfIssue(match, location, url, pair));
            }
        }
        publishStatus();
    }

    private void reportActiveFinding(ActiveTestEngine.ActiveFinding finding, HttpRequest base) {
        VerificationState state = finding.verificationState() == null
                ? VerificationState.SIGNAL : finding.verificationState();
        String status = state.displayLabel();
        String dedupe = "active\0" + (finding.evidenceRecord() == null ? "" : finding.evidenceRecord().runId()) + "\0" + finding.testClass() + "\0" + finding.parameter()
                + "\0" + finding.url() + "\0" + finding.evidence();
        if (!activeDedupe.add(dedupe)) return;

        FindingEvidence evidence = finding.evidenceRecord() == null
                ? FindingEvidence.metadata(finding.testClass(), state, "Detector emitted no structured capture: " + finding.evidence())
                : finding.evidenceRecord();
        addActiveRow(finding.severity(), finding.testClass(), finding.parameter(), status, finding.evidence(), finding.url(), evidence);

        if (state.isReportable() && !"INFO".equals(finding.severity())) {
            AuditIssueSeverity severity = switch (finding.severity()) {
                case "HIGH" -> AuditIssueSeverity.HIGH;
                case "MEDIUM" -> AuditIssueSeverity.MEDIUM;
                default -> AuditIssueSeverity.LOW;
            };
            String detail = "<b>Active test: " + escape(finding.testClass()) + "</b><br>"
                    + "Parameter: <code>" + escape(finding.parameter()) + "</code><br>"
                    + "Evidence: " + escape(finding.evidence());
            java.util.Optional<NucleiTemplateBuilder.PocSpec> poc = NucleiTemplateBuilder.fromActiveFinding(
                    finding.testClass(), finding.severity(), finding.url(), finding.parameter(), finding.evidence());
            if (poc.isPresent()) {
                detail += "<br><br><b>Runnable Nuclei PoC</b> (re-proves this finding — run against an "
                        + "authorised target):<br><pre>" + escape(NucleiTemplateBuilder.build(poc.get())) + "</pre>";
            }
            AuditIssueConfidence confidence = state == VerificationState.REPRODUCED
                    ? AuditIssueConfidence.FIRM : AuditIssueConfidence.CERTAIN;
            reporter.report(
                    "active-issue\0" + finding.testClass() + "\0" + finding.parameter() + "\0" + finding.url(),
                    finding.testClass() + " (" + finding.parameter() + ")",
                    detail + evidenceDetail(evidence),
                    activeRemediation(finding.testClass()),
                    finding.url(), severity, confidence,
                    "Recon Hound actively probes parameters for SSRF, SSTI and XSS when active testing is enabled. "
                            + "Verification state: " + state.displayLabel() + ".",
                    "Confirm the impact manually and only test targets you are authorised to assess.",
                    finding.httpEvidence().toArray(HttpRequestResponse[]::new));
        }
    }

    private void addActiveRow(String severity, String testClass, String parameter, String status, String evidence, String url) {
        addActiveRow(severity, testClass, parameter, status, evidence, url,
                FindingEvidence.metadata(testClass, VerificationState.SIGNAL, "Unstructured observation; status text is not verification evidence."));
    }

    private void addActiveRow(String severity, String testClass, String parameter, String status, String summary,
                              String url, FindingEvidence evidence) {
        if (!running.get()) return;
        if (Set.of("NATIVE_ACTIVE", "CORPUS", "NATIVE_HELPER").contains(evidence.source())
                && !activeRuns.ownsCurrentRun(evidence.runId())) return;
        ReconModel.ActiveRow row = new ReconModel.ActiveRow(severity, testClass, parameter, status, summary, url, evidence);
        runHistory.finding(row);
        long generation = stateGeneration.get();
        SwingUtilities.invokeLater(() -> {
            if (generation == stateGeneration.get()) activeModel.add(row);
        });
    }

    private static String evidenceDetail(FindingEvidence evidence) {
        return "<br>Verification state: <b>" + evidence.state().displayLabel() + "</b><br>Evidence ID: <code>" + escape(evidence.id()) + "</code>"
                + "<br>Detector: <code>" + escape(evidence.detectorId()) + " @ " + escape(evidence.detectorVersion()) + "</code>"
                + "<br>Rationale: " + escape(evidence.rationale()) + "<br>Reproduction: " + escape(evidence.reproduction())
                + "<br>Retained capture: " + (evidence.complete() ? "complete" : "partial / metadata; inspect capture flags");
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
                FindingEvidence.Oob event = OobEvidence.capture(interaction);
                if (oobDedupe.contains(event.fingerprint())) continue;
                long generation = stateGeneration.get();
                SwingUtilities.invokeLater(() -> {
                    if (!running.get() || generation != stateGeneration.get() || oobDedupe.contains(event.fingerprint())) return;
                    ReconModel.ActiveRow row = OobEvidence.link(event, activeModel.snapshot());
                    runHistory.finding(row);
                    activeModel.add(row); // Stable event ID upgrades a previously unlinked observation in place.
                    if (row.verificationState() != VerificationState.CONFIRMED) return;
                    oobDedupe.add(event.fingerprint());
                    reporter.report("oob-issue\0" + event.fingerprint(), "Correlated out-of-band interaction: " + row.testClass(),
                            "<b>Correlated Collaborator interaction</b><br>" + escape(row.evidence())
                                    + "<br>Payload ID: <code>" + escape(event.payloadId()) + "</code><br>Observed: " + escape(event.timestamp())
                                    + "<br>Interaction: " + escape(event.type()) + " from " + escape(event.clientIp()) + ":" + event.clientPort()
                                    + evidenceDetail(row.evidenceRecord()), activeRemediation(row.testClass()), row.url(),
                            AuditIssueSeverity.HIGH, AuditIssueConfidence.FIRM,
                            "Observed callback matched an issued payload with a retained API dispatch attempt.",
                            "A callback alone does not establish the exact exploit mechanism or impact.");
                    publishStatus();
                });
            }
        } catch (Exception e) { api.logging().logToError("Collaborator poll failed", e); }
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

    private String observationRunId() { ScanRun run = observationRun.get(); return run == null ? "" : run.id().toString(); }
    private void addFindingRow(ReconModel.FindingRow observation) {
        var row = observation.withRun(observationRunId());
        runHistory.finding(row);
        long generation = stateGeneration.get();
        SwingUtilities.invokeLater(() -> { if (generation == stateGeneration.get()) findingModel.add(row); });
    }

    private void addSyntheticFinding(String severity, String provider, String rule, String location, String value, String url) {
        String dedupe = "synthetic\0" + observationRunId() + "\0" + provider + "\0" + rule + "\0" + value + "\0" + url;
        if (!issueDedupe.add(dedupe)) return;
        String safe = value == null ? "" : (value.length() > 220 ? value.substring(0, 217) + "..." : value);
        addFindingRow(new ReconModel.FindingRow(
                severity, provider, rule, location, safe, url
        ));
    }

    private boolean includeGfMatch(GfPatternLoader.GfMatch match) {
        return !"INFO".equals(match.severity()) || match.category().equals("unclassified") || includeInfoFindings.get();
    }

    private AuditIssue buildGfIssue(GfPatternLoader.GfMatch match, String location, String url, HttpRequestResponse pair) {
        boolean sensitive = match.sensitive();
        String detail = "<b>GF pattern candidate</b><br>Pack: <code>" + escape(match.pack())
                + "</code><br>Rule: <code>" + escape(match.ruleId()) + "</code><br>Provider: " + escape(match.provider())
                + "<br>Category: " + escape(match.category()) + "<br>Location: " + escape(location)
                + "<br>Matched value: <code>" + escape(match.displayValue()) + "</code><br>"
                + "Verification state: <b>SIGNAL</b>. This is a passive format/context match; credential validity, permissions "
                + "and vulnerability impact have not been verified. Public identifiers and resource locations are inventory hints.";
        return reporter.buildIfNew("gf-issue\0" + match.pack() + "\0" + match.ruleId() + "\0" + match.value() + "\0" + url,
                "GF " + match.category() + " candidate (" + match.ruleId() + ")", detail,
                sensitive ? "Review the original evidence; rotate and restrict a credential if its exposure is confirmed."
                        : "Review the inventory/context before investigating the associated resource.",
                match.displaySourceUrl(url), IssueReporter.severity(match.severity()), AuditIssueConfidence.TENTATIVE,
                "Passive matching against local versioned GF patterns; no external engine or provider validation runs.",
                "A pattern match does not establish a usable credential or a vulnerability.", pair);
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
            if (scanGfPatterns.get()) {
                for (var match : gfPatterns.scan(response.toString())) if (includeGfMatch(match))
                    addIfPresent(issues, buildGfIssue(match, "scan-response", url, rr));
                for (var match : gfPatterns.scan(request.toString())) if (includeGfMatch(match))
                    addIfPresent(issues, buildGfIssue(match, "scan-request", url, rr));
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
            issues.addAll(dataExposureIssues(url, request, response, rr));
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
