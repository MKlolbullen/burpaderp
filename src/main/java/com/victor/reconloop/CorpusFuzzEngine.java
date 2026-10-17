package com.victor.reconloop;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.CollaboratorPayload;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Opt-in corpus-based fuzzing: replays the bundled raw payload corpus ({@code payloads/*.txt}, see
 * {@link PayloadLibrary}) against heuristically relevant parameters, trying one or more encodings
 * (raw / URL / HTML-entity / Base64, and chained combinations of those) per payload.
 *
 * <p>Deliberately kept separate from {@link ActiveTestEngine}'s small, self-authored payload set:
 * this corpus is large and third-party-sourced, and some of it needs filtering (persistent OS/account
 * changes, webshell planting) or rewriting (hardcoded external callback hosts, redirected to this
 * Burp instance's own Collaborator client instead) before it's safe to fire automatically. Never
 * invoked implicitly by crawling or passive scanning — only a deliberate user action runs this.
 */
final class CorpusFuzzEngine {
    private static final String DETECTOR_VERSION = "corpus-fuzz/1";

    // Never auto-fired regardless of settings: persistent/destructive changes, not test signals.
    // Bind/listen netcat shells, Windows account/group and firewall/registry changes, and writing an
    // executable webshell to disk are all a different order of risk than reading a file or sleeping.
    private static final Pattern DESTRUCTIVE = Pattern.compile(
            "\\bnc\\s+-[a-zA-Z]*l[a-zA-Z]*\\b|\\bncat\\s+-[a-zA-Z]*l[a-zA-Z]*\\b|"
                    + "\\bnet\\s+user\\b|\\bnet\\s+localgroup\\b|\\breg\\s+add\\b|\\bnetsh\\s+firewall\\b|"
                    + ">\\s*\\S+\\.(php|jsp|asp|aspx|pl|py|sh)\\b",
            Pattern.CASE_INSENSITIVE);

    // curl/wget payloads that "phone home" to a hardcoded third-party host: rewritten to this
    // instance's own Collaborator payload (a controlled, confirmable destination) rather than fired
    // at a domain/IP neither we nor the user running the test controls.
    private static final Pattern CALLBACK_HOST = Pattern.compile(
            "(?:curl|wget)\\s+(?:-\\S+\\s+)*[\"']?(?:https?://)?([a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}|(?:\\d{1,3}\\.){3}\\d{1,3})",
            Pattern.CASE_INSENSITIVE);

    private static final Pattern SLEEP_MARKER = Pattern.compile(
            "sleep\\s*\\(|pg_sleep|waitfor\\s+delay|benchmark\\s*\\(|dbms_lock\\.sleep", Pattern.CASE_INSENSITIVE);

    private static final Pattern PASSWD_MARKER = Pattern.compile("root:[^:\\r\\n]*:0:0:");
    private static final Pattern ID_OUTPUT = Pattern.compile("uid=\\d+[^\\r\\n]*gid=\\d+");
    private static final Pattern RCE_HINT_PARAM = Pattern.compile("\\?([a-zA-Z0-9_]+)=");

    private static final Set<String> PATH_NAME_HINTS = Set.of(
            "file", "path", "page", "doc", "document", "template", "include", "dir", "folder",
            "load", "filename", "filepath", "download", "resource", "view");
    private static final List<String> UNIVERSAL_CATEGORIES = List.of("sqli", "sqli2", "xss", "ssti");
    private static final int TIME_BASED_DELAY_SECONDS = 5;

    private final MontoyaApi api;
    private final PayloadLibrary library;
    private final long throttleMillis;
    private final Set<String> rceParamHints;
    private volatile CollaboratorClient collaborator;

    CorpusFuzzEngine(MontoyaApi api, PayloadLibrary library, long throttleMillis) {
        this.api = api;
        this.library = library;
        this.throttleMillis = throttleMillis;
        this.rceParamHints = parseRceParamHints(library.get("rce"));
    }

    void setCollaborator(CollaboratorClient collaborator) { this.collaborator = collaborator; }

    /**
     * Fuzzes one parameter with the relevant corpus categories, in every requested encoding.
     * {@code maxPerCategory} remains a local category cap, while the caller-owned {@link ScanRun}
     * provides the hard whole-run cap shared across every target/parameter/category.
     */
    List<ActiveTestEngine.ActiveFinding> fuzz(HttpRequest base, HttpParameter parameter,
                                               Set<PayloadEncoder.Encoding> encodings, int maxPerCategory) {
        return fuzz(base, parameter, encodings, maxPerCategory, false);
    }

    /** Compatibility entry point for callers that do not yet own a first-class run. */
    List<ActiveTestEngine.ActiveFinding> fuzz(HttpRequest base, HttpParameter parameter,
                                               Set<PayloadEncoder.Encoding> encodings, int maxPerCategory,
                                               boolean allowMutating) {
        if (base == null || parameter == null || maxPerCategory <= 0) return List.of();
        if (!allowMutating && !ActiveTestEngine.isSafeMethod(base)) return List.of();
        int categories = Math.max(1, relevantCategories(parameter.name(), parameter.value(),
                rceParamHints, library.categories()).size());
        ScanProfile profile = allowMutating ? ScanProfile.ACTIVE_MUTATION : ScanProfile.ACTIVE_SAFE;
        ScanRun run = ScanRun.begin(profile, ScopeSnapshot.forTargetUrl(base.url()),
                Math.max(1, maxPerCategory * categories));
        EnumSet<RequestPolicy.Permission> permissions = EnumSet.of(
                RequestPolicy.Permission.OAST,
                RequestPolicy.Permission.TIME_DELAY);
        if (allowMutating) {
            permissions.add(RequestPolicy.Permission.UNSAFE_HTTP_METHOD);
            permissions.add(RequestPolicy.Permission.STATE_CHANGING);
        }
        ActiveRequestGateway gateway = new ActiveRequestGateway(
                new RequestPolicy(api.scope()::isInScope, permissions), api.http()::sendRequest);
        try {
            return fuzz(base, parameter, encodings, maxPerCategory, run, gateway);
        } finally {
            if (run.isRunning()) run.complete();
        }
    }

    List<ActiveTestEngine.ActiveFinding> fuzz(HttpRequest base, HttpParameter parameter,
                                               Set<PayloadEncoder.Encoding> encodings, int maxPerCategory,
                                               ScanRun run, ActiveRequestGateway gateway) {
        List<ActiveTestEngine.ActiveFinding> out = new ArrayList<>();
        if (base == null || parameter == null || encodings == null || encodings.isEmpty()
                || maxPerCategory <= 0 || run == null || gateway == null || !run.isRunning()) return out;

        for (String category : relevantCategories(parameter.name(), parameter.value(), rceParamHints, library.categories())) {
            RequestBudget categoryBudget = new RequestBudget(maxPerCategory);
            for (String rawPayload : library.get(category)) {
                if (categoryBudget.exhausted() || run.requestBudget().exhausted() || !run.isRunning()) break;
                if (isDestructive(rawPayload)) continue;

                String payload = rawPayload;
                boolean oastPayload = findCallbackHost(rawPayload).isPresent();
                if (oastPayload) {
                    CollaboratorClient client = collaborator;
                    if (client == null) continue;
                    CollaboratorPayload oobPayload = client.generatePayload(
                            ActiveTestEngine.encodeCorrelation("CorpusFuzz-" + category, parameter.name(), base.url()));
                    payload = rewriteCallbackHost(rawPayload, oobPayload.toString());
                }

                boolean timeBased = mentionsSleep(payload);
                for (PayloadEncoder.Encoding encoding : encodings) {
                    if (categoryBudget.exhausted() || run.requestBudget().exhausted() || !run.isRunning()) break;
                    String encoded = PayloadEncoder.encode(payload, encoding);

                    if (timeBased) {
                        // A timing comparison needs baseline + mutation from both the local category
                        // quota and the global run quota. Never spend the final token on half a pair.
                        if (categoryBudget.remaining() < 2 || run.requestBudget().remaining() < 2) break;
                        EnumSet<RequestPolicy.Permission> timingPermissions =
                                EnumSet.of(RequestPolicy.Permission.TIME_DELAY);
                        if (oastPayload) timingPermissions.add(RequestPolicy.Permission.OAST);
                        long baselineMillis = timeRequest(base, parameter, parameter.value(),
                                categoryBudget, run, gateway, category, timingPermissions);
                        if (baselineMillis < 0) break;
                        long payloadMillis = timeRequest(base, parameter, encoded,
                                categoryBudget, run, gateway, category, timingPermissions);
                        if (baselineMillis >= 0 && payloadMillis >= 0
                                && ActiveTestEngine.looksTimeBased(baselineMillis, payloadMillis, TIME_BASED_DELAY_SECONDS)) {
                            out.add(finding("HIGH", "CorpusFuzz-" + category, parameter.name(),
                                    "[" + encoding + "] time-based signal from corpus payload: " + truncate(rawPayload),
                                    VerificationState.CANDIDATE, base.url(), run, category, encoded));
                        }
                        continue;
                    }

                    Set<RequestPolicy.Permission> payloadPermissions = oastPayload
                            ? Set.of(RequestPolicy.Permission.OAST) : Set.of();
                    HttpResponse response = sendMutated(base, parameter, encoded, categoryBudget, run, gateway,
                            category, payloadPermissions);
                    if (response == null) continue;
                    String body = response.bodyToString();

                    if (("sqli".equals(category) || "sqli2".equals(category)) && ActiveTestEngine.containsSqlError(body)) {
                        out.add(finding("HIGH", "CorpusFuzz-" + category, parameter.name(),
                                "[" + encoding + "] database error signature from corpus payload: " + truncate(rawPayload),
                                VerificationState.REPRODUCED, base.url(), run, category, encoded));
                    } else if ("lfi".equals(category) && containsPasswdMarker(body)) {
                        out.add(finding("HIGH", "CorpusFuzz-lfi", parameter.name(),
                                "[" + encoding + "] /etc/passwd contents returned for corpus payload: " + truncate(rawPayload),
                                VerificationState.REPRODUCED, base.url(), run, category, encoded));
                    } else if ("rce_payloads".equals(category) && containsIdOutput(body)) {
                        out.add(finding("HIGH", "CorpusFuzz-rce", parameter.name(),
                                "[" + encoding + "] command output (uid=.../gid=...) returned for corpus payload: " + truncate(rawPayload),
                                VerificationState.CONFIRMED, base.url(), run, category, encoded));
                    } else if (body != null && !rawPayload.isBlank() && body.contains(rawPayload)) {
                        out.add(finding("MEDIUM", "CorpusFuzz-" + category, parameter.name(),
                                "[" + encoding + "] payload reflected unencoded in response: " + truncate(rawPayload),
                                VerificationState.CANDIDATE, base.url(), run, category, encoded));
                    }
                }
            }
        }
        return out;
    }

    private ActiveTestEngine.ActiveFinding finding(
            String severity, String testClass, String parameter, String evidence,
            VerificationState state, String url, ScanRun run, String category, String mutation) {
        String mutationSummary = parameter + " => " + truncate(mutation);
        FindingEvidence provenance = FindingEvidence.active(
                run,
                "corpus-fuzz:" + category,
                DETECTOR_VERSION,
                mutationSummary,
                state,
                testClass,
                parameter,
                url,
                evidence);
        return new ActiveTestEngine.ActiveFinding(
                severity, testClass, parameter, evidence, state, url, provenance);
    }

    private HttpResponse sendMutated(HttpRequest base, HttpParameter parameter, String value,
                                     RequestBudget categoryBudget, ScanRun run, ActiveRequestGateway gateway,
                                     String category, Set<RequestPolicy.Permission> extraPermissions) {
        try {
            if (categoryBudget.exhausted()) return null;
            HttpParameter mutated = HttpParameter.parameter(parameter.name(), value, parameter.type());
            HttpRequest request = base.withUpdatedParameters(mutated);
            EnumSet<RequestPolicy.Permission> permissions = EnumSet.noneOf(RequestPolicy.Permission.class);
            if (extraPermissions != null) permissions.addAll(extraPermissions);
            if (!ActiveTestEngine.isSafeMethod(request)) {
                permissions.add(RequestPolicy.Permission.UNSAFE_HTTP_METHOD);
                permissions.add(RequestPolicy.Permission.STATE_CHANGING);
            }
            ActiveRequestGateway.Result result = gateway.send(run,
                    new RequestPolicy.PlannedRequest(request.method(), request.url(),
                            "corpus-fuzz:" + category, permissions),
                    request);
            if (result.error() != null) {
                api.logging().logToError("Corpus fuzz probe failed for " + parameter.name(), result.error());
                return null;
            }
            if (!result.dispatched()) return null;
            // This fuzzer is serialized per invocation, so charging the local category quota after
            // gateway dispatch is safe and ensures policy/quota denials do not consume corpus quota.
            if (!categoryBudget.tryAcquire()) return null;
            throttle();
            return result.response() == null ? null : result.response().response();
        } catch (Exception e) {
            api.logging().logToError("Corpus fuzz probe failed for " + parameter.name(), e);
            return null;
        }
    }

    private long timeRequest(HttpRequest base, HttpParameter parameter, String value,
                             RequestBudget categoryBudget, ScanRun run, ActiveRequestGateway gateway,
                             String category, Set<RequestPolicy.Permission> permissions) {
        if (categoryBudget.exhausted() || run.requestBudget().exhausted() || !run.isRunning()) return -1;
        long start = System.currentTimeMillis();
        int categoryBefore = categoryBudget.used();
        int runBefore = run.requestBudget().used();
        sendMutated(base, parameter, value, categoryBudget, run, gateway, category, permissions);
        if (categoryBudget.used() == categoryBefore || run.requestBudget().used() == runBefore) return -1;
        return System.currentTimeMillis() - start;
    }

    private void throttle() {
        if (throttleMillis <= 0) return;
        try { Thread.sleep(throttleMillis); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
    }

    private static String truncate(String s) {
        if (s == null) return "";
        return s.length() <= 120 ? s : s.substring(0, 120) + "...";
    }

    // ---- pure cores (unit-tested) ----

    static boolean isDestructive(String payload) {
        return payload != null && DESTRUCTIVE.matcher(payload).find();
    }

    static boolean mentionsSleep(String payload) {
        return payload != null && SLEEP_MARKER.matcher(payload).find();
    }

    static boolean containsPasswdMarker(String body) {
        return body != null && PASSWD_MARKER.matcher(body).find();
    }

    static boolean containsIdOutput(String body) {
        return body != null && ID_OUTPUT.matcher(body).find();
    }

    /** Extracts the callback host from a curl/wget-shaped payload, or empty if none is present. */
    static Optional<String> findCallbackHost(String payload) {
        if (payload == null) return Optional.empty();
        Matcher m = CALLBACK_HOST.matcher(payload);
        return m.find() ? Optional.of(m.group(1)) : Optional.empty();
    }

    /** Replaces an embedded curl/wget callback host with {@code replacementHost}, preserving the rest of the payload. */
    static String rewriteCallbackHost(String payload, String replacementHost) {
        if (payload == null) return null;
        Matcher m = CALLBACK_HOST.matcher(payload);
        if (!m.find()) return payload;
        return payload.substring(0, m.start(1)) + replacementHost + payload.substring(m.end(1));
    }

    /** Parses {@code rce.txt}'s {@code ?name={payload}} injection-point hints into a bare parameter-name set. */
    static Set<String> parseRceParamHints(List<String> hintLines) {
        Set<String> names = new LinkedHashSet<>();
        if (hintLines == null) return names;
        for (String line : hintLines) {
            Matcher m = RCE_HINT_PARAM.matcher(line);
            if (m.find()) names.add(m.group(1).toLowerCase(Locale.ROOT));
        }
        return names;
    }

    /** Decides which corpus categories are worth trying against this parameter. */
    static List<String> relevantCategories(String paramName, String paramValue,
                                            Set<String> rceParamHints, Set<String> availableCategories) {
        List<String> categories = new ArrayList<>();
        String name = paramName == null ? "" : paramName.toLowerCase(Locale.ROOT);
        String value = paramValue == null ? "" : paramValue;

        for (String universal : UNIVERSAL_CATEGORIES) {
            if (availableCategories.contains(universal)) categories.add(universal);
        }

        boolean looksLikePath = PATH_NAME_HINTS.stream().anyMatch(name::contains)
                || value.contains("/") || value.contains("\\");
        if (looksLikePath && availableCategories.contains("lfi")) categories.add("lfi");

        boolean looksLikeCommandSink = rceParamHints.contains(name);
        if (looksLikeCommandSink && availableCategories.contains("rce_payloads")) categories.add("rce_payloads");

        return categories;
    }
}
