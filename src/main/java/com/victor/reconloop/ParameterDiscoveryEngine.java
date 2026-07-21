package com.victor.reconloop;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.io.IOException;
import java.nio.file.*;
import java.util.*;

/**
 * Arjun-style hidden/unlinked parameter discovery.
 *
 * <p>Given an in-scope request, probes a wordlist of common parameter names in chunks. A candidate
 * is reported when its unique canary value is reflected in the response, or when adding it produces
 * a material change in response length or status versus the baseline. This is active traffic: it is
 * only driven from the opt-in active-testing controls, is scope-checked per request, throttled, and
 * request-capped.
 */
final class ParameterDiscoveryEngine {

    record Discovered(String name, String evidence, String url) {}

    private static final int CHUNK = 20;
    private static final int LENGTH_DELTA = 24;

    private final MontoyaApi api;
    private final List<String> wordlist;

    ParameterDiscoveryEngine(MontoyaApi api) {
        this.api = api;
        this.wordlist = loadWordlist();
    }

    int wordlistSize() { return wordlist.size(); }

    List<Discovered> discover(HttpRequest base, int maxRequests, long throttleMillis) {
        if (base == null) return List.of();
        HttpRequest seed = base.withMethod("GET");
        String url = seed.url();

        HttpRequestResponse baseline = send(seed);
        if (baseline == null || baseline.response() == null) return List.of();
        int baselineLength = baseline.response().bodyToString().length();
        short baselineStatus = baseline.response().statusCode();

        List<Discovered> discovered = new ArrayList<>();
        Set<String> reported = new HashSet<>();
        int sent = 1;

        for (int i = 0; i < wordlist.size() && sent < maxRequests; i += CHUNK) {
            List<String> chunk = wordlist.subList(i, Math.min(i + CHUNK, wordlist.size()));

            Map<String, String> canaries = new LinkedHashMap<>();
            List<HttpParameter> params = new ArrayList<>();
            for (String name : chunk) {
                if (seed.hasParameter(name, HttpParameter.urlParameter(name, "").type())) continue;
                String canary = canaryFor(name);
                canaries.put(name, canary);
                params.add(HttpParameter.urlParameter(name, canary));
            }
            if (params.isEmpty()) continue;

            HttpRequest probe = seed.withAddedParameters(params);
            HttpRequestResponse rr = send(probe);
            sent++;
            throttle(throttleMillis);
            if (rr == null || rr.response() == null) continue;

            HttpResponse response = rr.response();
            String body = response.bodyToString();

            for (String name : reflectedNames(body, canaries)) {
                if (reported.add(name)) {
                    discovered.add(new Discovered(name, "value reflected in response", url));
                }
            }

            int delta = Math.abs(body.length() - baselineLength);
            if ((response.statusCode() != baselineStatus || delta > LENGTH_DELTA) && chunk.size() == 1) {
                String name = chunk.get(0);
                if (reported.add(name)) {
                    discovered.add(new Discovered(name,
                            "response changed (status " + response.statusCode() + ", Δlen " + delta + ")", url));
                }
            }
        }
        return discovered;
    }

    /** Pure core: names whose canary value appears in the response body. */
    static List<String> reflectedNames(String body, Map<String, String> nameToCanary) {
        if (body == null || body.isEmpty()) return List.of();
        List<String> names = new ArrayList<>();
        for (Map.Entry<String, String> entry : nameToCanary.entrySet()) {
            if (body.contains(entry.getValue())) names.add(entry.getKey());
        }
        return names;
    }

    /** Deterministic, collision-resistant, easily searchable canary that is not a natural substring. */
    static String canaryFor(String name) {
        int h = name.hashCode() & 0x7fffffff;
        return "rh" + Integer.toString(h, 36) + "zq";
    }

    private HttpRequestResponse send(HttpRequest request) {
        try {
            if (!api.scope().isInScope(request.url())) return null;
            return api.http().sendRequest(request);
        } catch (Exception e) {
            api.logging().logToError("Parameter discovery request failed", e);
            return null;
        }
    }

    private static void throttle(long millis) {
        if (millis <= 0) return;
        try { Thread.sleep(millis); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
    }

    private List<String> loadWordlist() {
        LinkedHashSet<String> names = new LinkedHashSet<>(DEFAULT_PARAMS);
        for (Path path : List.of(
                Path.of(System.getProperty("user.home"), ".recon-hound", "params.txt"),
                Path.of("params.txt"))) {
            if (!Files.isRegularFile(path)) continue;
            try {
                for (String line : Files.readAllLines(path)) {
                    String value = line.trim();
                    if (!value.isEmpty() && !value.startsWith("#")) names.add(value);
                }
            } catch (IOException ignored) {}
        }
        return List.copyOf(names);
    }

    static final List<String> DEFAULT_PARAMS = List.of(
            "id", "page", "q", "query", "search", "s", "keyword", "lang", "locale", "url", "uri",
            "redirect", "redirect_uri", "redirect_url", "return", "returnurl", "returnto", "next",
            "continue", "goto", "dest", "destination", "callback", "cb", "jsonp", "file", "filename",
            "path", "dir", "folder", "download", "document", "doc", "template", "view", "theme",
            "layout", "include", "action", "do", "op", "operation", "cmd", "command", "exec", "func",
            "function", "method", "module", "type", "format", "mode", "debug", "test", "admin",
            "token", "api_key", "apikey", "key", "secret", "auth", "session", "user", "user_id",
            "userid", "uid", "account", "email", "name", "username", "role", "group", "order",
            "sort", "sortby", "filter", "category", "cat", "tag", "product", "item", "sku", "code",
            "ref", "referrer", "source", "utm_source", "campaign", "lang_id", "country", "city",
            "state", "zip", "date", "start", "end", "from", "to", "limit", "offset", "count", "size",
            "per_page", "pagesize", "fields", "select", "columns", "table", "db", "database", "host",
            "port", "proxy", "target", "domain", "ip", "server", "endpoint", "webhook", "feed",
            "image", "img", "avatar", "logo", "src", "data", "value", "val", "content", "message",
            "msg", "text", "title", "subject", "body", "html", "xml", "json", "yaml", "config",
            "settings", "option", "flag", "enable", "disable", "show", "hide", "preview", "raw",
            "output", "render", "print", "export", "import", "upload", "process");
}
