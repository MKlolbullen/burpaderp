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
    private final ThreadLocal<EvidenceCapture> evidenceCapture = new ThreadLocal<>();
    private volatile CollaboratorClient collaborator;

    CorpusFuzzEngine(MontoyaApi api, PayloadLibrary library, long throttleMillis) {
        this.api = api;
        this.library = library;
        this.throttleMillis = throttleMillis;
        this.rceParamHints = parseRceParamHints(library.get("rce"));
    }

    void setCollaborator(CollaboratorClient collaborator) { this.collaborator = collaborator; }

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

                EvidenceCapture prototype = new EvidenceCapture(run, base, "CORPUS", "corpus-fuzz:" + category);
                String callbackHost = null;
                boolean oastPayload = findCallbackHost(rawPayload).isPresent();
                if (oastPayload) {
                    CollaboratorClient client = collaborator;
                    if (client == null) continue;
                    CollaboratorPayload oobPayload = client.generatePayload(
                            prototype.correlation());
                    prototype.issued(oobPayload, "CorpusFuzz-" + category, parameter.name());
                    callbackHost = oobPayload.toString();
                }

                boolean timeBased = mentionsSleep(rawPayload);
                for (PayloadEncoder.Encoding encoding : encodings.stream().sorted().toList()) {
                    if (categoryBudget.exhausted() || run.requestBudget().exhausted() || !run.isRunning()) break;
                    String encoded = encodedPayload(rawPayload, callbackHost, encoding);
                    EvidenceCapture capture = prototype.variant(base);
                    evidenceCapture.set(capture); int firstFinding = out.size();
                    try {

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
                                out.add(new ActiveTestEngine.ActiveFinding("HIGH", "CorpusFuzz-" + category, parameter.name(),
                                        "[" + encoding + "] time-based signal from corpus payload: " + truncate(rawPayload),
                                        VerificationState.CANDIDATE, base.url()));
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
                            out.add(new ActiveTestEngine.ActiveFinding("HIGH", "CorpusFuzz-" + category, parameter.name(),
                                    "[" + encoding + "] database error signature from corpus payload: " + truncate(rawPayload),
                                    VerificationState.REPRODUCED, base.url()));
                        } else if ("lfi".equals(category) && containsPasswdMarker(body)) {
                            out.add(new ActiveTestEngine.ActiveFinding("HIGH", "CorpusFuzz-lfi", parameter.name(),
                                    "[" + encoding + "] /etc/passwd contents returned for corpus payload: " + truncate(rawPayload),
                                    VerificationState.REPRODUCED, base.url()));
                        } else if ("rce_payloads".equals(category) && containsIdOutput(body)) {
                            out.add(new ActiveTestEngine.ActiveFinding("HIGH", "CorpusFuzz-rce", parameter.name(),
                                    "[" + encoding + "] command output (uid=.../gid=...) returned for corpus payload: " + truncate(rawPayload),
                                    VerificationState.CONFIRMED, base.url()));
                        } else if (body != null && !rawPayload.isBlank() && body.contains(rawPayload)) {
                            out.add(new ActiveTestEngine.ActiveFinding("MEDIUM", "CorpusFuzz-" + category, parameter.name(),
                                    "[" + encoding + "] payload reflected unencoded in response: " + truncate(rawPayload),
                                    VerificationState.CANDIDATE, base.url()));
                        }
                    } finally { capture.attach(out, firstFinding); evidenceCapture.remove(); }
                }
            }
        }
        return out;
    }

    /** All candidate encodings, with the same raw risk classification and local category caps as execution. */
    Iterable<NativeRequestStep> plan(HttpRequest base, HttpParameter parameter,
                                   Set<PayloadEncoder.Encoding> encodings, int maxPerCategory) {
        return plan(base, parameter, encodings, maxPerCategory, null);
    }

    Iterable<NativeRequestStep> plan(HttpRequest base, HttpParameter parameter, Set<PayloadEncoder.Encoding> encodings,
                                   int maxPerCategory, String categoryFilter) {
        List<PayloadEncoder.Encoding> selected = encodings.stream().sorted().toList();
        return () -> {
            List<String> categories = maxPerCategory <= 0 ? List.of()
                    : relevantCategories(parameter.name(), parameter.value(), rceParamHints, library.categories());
            return categories.stream().filter(category -> categoryFilter == null || category.equals(categoryFilter)).flatMap(category -> {
                Object localKey = new Object();
                return java.util.stream.IntStream.range(0, library.get(category).size()).boxed()
                        .filter(i -> !isDestructive(library.get(category).get(i)))
                        .flatMap(i -> selected.stream().flatMap(encoding -> {
                            String raw = library.get(category).get(i);
                            boolean oast = findCallbackHost(raw).isPresent();
                            boolean timing = mentionsSleep(raw);
                            Set<RequestPolicy.Permission> risks = risks(oast, timing);
                            String detail = "parameter " + parameter.name() + "; " + category + " entry " + (i + 1) + "; " + encoding
                                    + "; local cap " + maxPerCategory;
                            java.util.function.Supplier<HttpRequest> mutation = () -> mutate(base, parameter,
                                    encodedPayload(raw, oast ? ActiveTestEngine.PREVIEW_CALLBACK : null, encoding));
                            NativeRequestRecipe payload = new NativeRequestRecipe(mutation, "corpus-fuzz:" + category, risks,
                                    NativeRequestStep.Mutation.CORPUS_VALUE, timing ? NativeRequestStep.Condition.PRIOR_DISPATCH
                                            : oast ? NativeRequestStep.Condition.RUNTIME_VALUE : NativeRequestStep.Condition.ALWAYS,
                                    detail, oast);
                            if (!timing) return java.util.stream.Stream.of(new java.util.AbstractMap.SimpleImmutableEntry<>(payload,
                                    new NativeRequestStep.Constraints(localKey, maxPerCategory, 1, null, null)));
                            Object pair = new Object();
                            NativeRequestRecipe baseline = new NativeRequestRecipe(() -> mutate(base, parameter, parameter.value()),
                                    "corpus-fuzz:" + category, risks, NativeRequestStep.Mutation.TIMING_BASELINE,
                                    NativeRequestStep.Condition.ALWAYS, detail + "; timing baseline", false);
                            return java.util.stream.Stream.of(
                                    new java.util.AbstractMap.SimpleImmutableEntry<>(baseline, new NativeRequestStep.Constraints(localKey, maxPerCategory, 2, null, pair)),
                                    new java.util.AbstractMap.SimpleImmutableEntry<>(payload, new NativeRequestStep.Constraints(localKey, maxPerCategory, 1, pair, null)));
                        }));
            }).map(entry -> entry.getKey().build().withConstraints(entry.getValue())).iterator();
        };
    }

    private static Set<RequestPolicy.Permission> risks(boolean oast, boolean timing) {
        EnumSet<RequestPolicy.Permission> risks = EnumSet.noneOf(RequestPolicy.Permission.class);
        if (oast) risks.add(RequestPolicy.Permission.OAST);
        if (timing) risks.add(RequestPolicy.Permission.TIME_DELAY);
        return Set.copyOf(risks);
    }

    private static HttpRequest mutate(HttpRequest base, HttpParameter parameter, String value) {
        return base.withUpdatedParameters(HttpParameter.parameter(parameter.name(), value, parameter.type()));
    }

    private static String encodedPayload(String raw, String callbackHost, PayloadEncoder.Encoding encoding) {
        return PayloadEncoder.encode(callbackHost == null ? raw : rewriteCallbackHost(raw, callbackHost), encoding);
    }

    private HttpResponse sendMutated(HttpRequest base, HttpParameter parameter, String value,
                                     RequestBudget categoryBudget, ScanRun run, ActiveRequestGateway gateway,
                                     String category, Set<RequestPolicy.Permission> extraPermissions) {
        try {
            if (categoryBudget.exhausted()) return null;
            HttpRequest request = mutate(base, parameter, value);
            EnumSet<RequestPolicy.Permission> permissions = EnumSet.noneOf(RequestPolicy.Permission.class);
            if (extraPermissions != null) permissions.addAll(extraPermissions);
            Set<RequestPolicy.Permission> required = NativeRequestRecipe.mutationPermissions(request, permissions);
            ActiveRequestGateway.Result result = gateway.send(run,
                    RequestPlan.create(request,
                            "corpus-fuzz:" + category, required),
                    request);
            if (evidenceCapture.get() != null) evidenceCapture.get().record(result, extraPermissions != null && extraPermissions.contains(RequestPolicy.Permission.OAST)
                    && !java.util.Objects.equals(value, parameter.value()));
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
