package com.victor.reconloop;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Passive subdomain enumeration via the crt.sh certificate-transparency log.
 *
 * <p>Queries {@code https://crt.sh/?q=%.<domain>&output=json} and extracts host names from the
 * {@code name_value} / {@code common_name} fields. This is OSINT: no request is ever sent to the
 * target itself, only to crt.sh. Discovered hosts are fed back into Recon Hound's discovery/scope
 * pipeline by the controller.
 */
final class CertificateTransparencyClient {

    private static final Pattern HOST_FIELD =
            Pattern.compile("\"(?:name_value|common_name)\"\\s*:\\s*\"((?:\\\\.|[^\"\\\\])*)\"");
    private static final Pattern VALID_HOST =
            Pattern.compile("^[a-z0-9](?:[a-z0-9-]{0,62})(?:\\.[a-z0-9](?:[a-z0-9-]{0,62}))+$");

    private final MontoyaApi api;

    CertificateTransparencyClient(MontoyaApi api) {
        this.api = api;
    }

    /** Fetches crt.sh for {@code domain} and returns the distinct subdomains found. */
    Set<String> enumerate(String domain) {
        String normalized = normalizeDomain(domain);
        if (normalized == null) return Set.of();

        String url = "https://crt.sh/?q=%25." + normalized + "&output=json";
        try {
            HttpRequest request = HttpRequest.httpRequestFromUrl(url)
                    .withMethod("GET")
                    .withUpdatedHeader("User-Agent", "Recon-Hound/0.2 (+burp)")
                    .withUpdatedHeader("Accept", "application/json");
            HttpRequestResponse rr = api.http().sendRequest(request);
            if (rr == null || rr.response() == null) return Set.of();
            return parseHosts(rr.response().bodyToString(), normalized);
        } catch (Exception e) {
            api.logging().logToError("crt.sh enumeration failed for " + normalized, e);
            return Set.of();
        }
    }

    /** Pure parser: extracts valid hosts under {@code rootDomain} from a crt.sh JSON body. */
    static Set<String> parseHosts(String json, String rootDomain) {
        if (json == null || json.isBlank()) return Set.of();
        String suffix = "." + rootDomain;
        TreeSet<String> hosts = new TreeSet<>();

        Matcher matcher = HOST_FIELD.matcher(json);
        while (matcher.find()) {
            String field = unescape(matcher.group(1));
            for (String candidate : field.split("[\\r\\n]+")) {
                String host = candidate.trim().toLowerCase(Locale.ROOT);
                if (host.startsWith("*.")) host = host.substring(2);
                if (host.isEmpty() || host.contains(" ") || host.contains("@")) continue;
                if (host.equals(rootDomain) || host.endsWith(suffix)) {
                    if (VALID_HOST.matcher(host).matches()) hosts.add(host);
                }
            }
        }
        return hosts;
    }

    static String normalizeDomain(String domain) {
        if (domain == null) return null;
        String value = domain.trim().toLowerCase(Locale.ROOT);
        if (value.startsWith("http://")) value = value.substring(7);
        if (value.startsWith("https://")) value = value.substring(8);
        int slash = value.indexOf('/');
        if (slash >= 0) value = value.substring(0, slash);
        int colon = value.indexOf(':');
        if (colon >= 0) value = value.substring(0, colon);
        if (value.startsWith("*.")) value = value.substring(2);
        return VALID_HOST.matcher(value).matches() ? value : null;
    }

    private static String unescape(String value) {
        return value.replace("\\n", "\n").replace("\\r", "\r")
                .replace("\\/", "/").replace("\\\"", "\"").replace("\\\\", "\\");
    }
}
