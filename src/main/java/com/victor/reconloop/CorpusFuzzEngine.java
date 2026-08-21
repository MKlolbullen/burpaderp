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
     * {@code maxPerCategory} is a hard outbound-request cap for each category. Timing probes consume
     * two budget tokens (baseline + mutated request), so they cannot silently overshoot the cap.
     */
    List<ActiveTestEngine.ActiveFinding> fuzz(HttpRequest base, HttpParameter parameter,
                                               Set<PayloadEncoder.Encoding> encodings, int maxPerCategory) {
        List<ActiveTestEngine.ActiveFinding> out = new ArrayList<>();
        if (base == null || parameter == null || encodings == null || encodings.isEmpty() || maxPerCategory <= 0) return out;

        for (String category : relevantCategories(parameter.name(), parameter.value(), rceParamHints, library.categories())) {
            RequestBudget budget = new RequestBudget(maxPerCategory);
            for (String rawPayload : library.get(category)) {
                if (budget.exhausted()) break;
                if (isDestructive(rawPayload)) continue;

                String payload = rawPayload;
                if (findCallbackHost(rawPayload).isPresent()) {
                    CollaboratorClient client = collaborator;
                    if (client == null) continue; // no controlled destination to rewrite to -- skip rather than call a stranger's host
                    CollaboratorPayload oobPayload = client.generatePayload(
                            ActiveTestEngine.encodeCorrelation("CorpusFuzz-" + category, parameter.name(), base.url()));
                    payload = rewriteCallbackHost(rawPayload, oobPayload.toString());
                }

                boolean timeBased = mentionsSleep(payload);
                for (PayloadEncoder.Encoding encoding : encodings) {
                    if (budget.exhausted()) break;
                    String encoded = PayloadEncoder.encode(payload, encoding);

                    if (timeBased) {
                        // A meaningful timing comparison needs both requests. Do not spend the final
                        // token on a baseline that can never be paired with its mutation.
                        if (budget.remaining() < 2) break;
                        long baselineMillis = timeRequest(base, parameter, parameter.value(), budget);
                        long payloadMillis = timeRequest(base, parameter, encoded, budget);
                        if (baselineMillis >= 0 && payloadMillis >= 0
                                && ActiveTestEngine.looksTimeBased(baselineMillis, payloadMillis, TIME_BASED_DELAY_SECONDS)) {
                            out.add(new ActiveTestEngine.ActiveFinding("HIGH", "CorpusFuzz-" + category, parameter.name(),
                                    "[" + encoding + "] time-based signal from corpus payload: " + truncate(rawPayload),
                                    true, base.url()));
                        }
                        continue;
                    }

                    HttpResponse response = sendMutated(base, parameter, encoded, budget);
                    if (response == null) continue;
                    String body = response.bodyToString();

                    if (("sqli".equals(category) || "sqli2".equals(category)) && ActiveTestEngine.containsSqlError(body)) {
                        out.add(new ActiveTestEngine.ActiveFinding("HIGH", "CorpusFuzz-" + category, parameter.name(),
                                "[" + encoding + "] database error signature from corpus payload: " + truncate(rawPayload),
                                true, base.url()));
                    } else if ("lfi".equals(category) && containsPasswdMarker(body)) {
                        out.add(new ActiveTestEngine.ActiveFinding("HIGH", "CorpusFuzz-lfi", parameter.name(),
                                "[" + encoding + "] /etc/passwd contents returned for corpus payload: " + truncate(rawPayload),
                                true, base.url()));
                    } else if ("rce_payloads".equals(category) && containsIdOutput(body)) {
                        out.add(new ActiveTestEngine.ActiveFinding("HIGH", "CorpusFuzz-rce", parameter.name(),
                                "[" + encoding + "] command output (uid=.../gid=...) returned for corpus payload: " + truncate(rawPayload),
                                true, base.url()));
                    } else if (body != null && !rawPayload.isBlank() && body.contains(rawPayload)) {
                        out.add(new ActiveTestEngine.ActiveFinding("MEDIUM", "CorpusFuzz-" + category, parameter.name(),
                                "[" + encoding + "] payload reflected unencoded in response: " + truncate(rawPayload),
                                true, base.url()));
                    }
                }
            }
        }
        return out;
    }

    private HttpResponse sendMutated(HttpRequest base, HttpParameter parameter, String value, RequestBudget budget) {
        try {
            if (!api.scope().isInScope(base.url())) return null;
            if (!budget.tryAcquire()) return null;
            HttpParameter mutated = HttpParameter.parameter(parameter.name(), value, parameter.type());
            HttpRequestResponse rr = api.http().sendRequest(base.withUpdatedParameters(mutated));
            throttle();
            return rr == null ? null : rr.response();
        } catch (Exception e) {
            api.logging().logToError("Corpus fuzz probe failed for " + parameter.name(), e);
            return null;
        }
    }

    private long timeRequest(HttpRequest base, HttpParameter parameter, String value, RequestBudget budget) {
        if (budget.exhausted()) return -1;
        long start = System.currentTimeMillis();
        int before = budget.used();
        sendMutated(base, parameter, value, budget);
        if (budget.used() == before) return -1;
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
