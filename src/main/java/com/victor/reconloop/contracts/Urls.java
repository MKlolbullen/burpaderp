package com.victor.reconloop.contracts;

import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;

final class Urls {
    private Urls() {}

    static String rejectReason(String raw) {
        if (raw == null || raw.isBlank()) return "empty URL";
        String s = raw.strip();
        String lower = s.toLowerCase(Locale.ROOT);
        if (lower.startsWith("javascript:") || lower.startsWith("data:")
                || lower.startsWith("mailto:") || lower.startsWith("file:")) {
            return "unsupported URL scheme";
        }
        URI uri;
        try {
            uri = URI.create(s);
        } catch (IllegalArgumentException e) {
            return "unparseable URL";
        }
        String scheme = uri.getScheme();
        if (scheme == null) return "URL is missing a scheme";
        scheme = scheme.toLowerCase(Locale.ROOT);
        if (!scheme.equals("http") && !scheme.equals("https")) return "unsupported URL scheme";
        if (uri.getHost() == null || uri.getHost().isBlank()) return "URL is missing a host";
        return null;
    }

    static URI normalize(String raw) {
        URI uri = URI.create(raw.strip());
        String scheme = uri.getScheme().toLowerCase(Locale.ROOT);
        String host = HostNames.canonical(uri.getHost());
        int port = uri.getPort();
        if ((scheme.equals("http") && port == 80) || (scheme.equals("https") && port == 443)) {
            port = -1;
        }
        String path = uri.getRawPath();
        if (path == null || path.isEmpty()) path = "/";
        String query = normalizeQuery(uri.getRawQuery());
        try {
            return new URI(scheme, null, host, port, path, query.isEmpty() ? null : query, null);
        } catch (Exception e) {
            return uri;
        }
    }

    static String normalizeQuery(String rawQuery) {
        if (rawQuery == null || rawQuery.isBlank()) return "";
        List<String[]> pairs = new ArrayList<>();
        for (String part : rawQuery.split("&")) {
            if (part.isEmpty()) continue;
            int eq = part.indexOf('=');
            String k = eq < 0 ? part : part.substring(0, eq);
            String v = eq < 0 ? "" : part.substring(eq + 1);
            pairs.add(new String[]{decode(k), decode(v)});
        }
        pairs.sort(Comparator.comparing((String[] p) -> p[0]).thenComparing(p -> p[1]));
        StringBuilder b = new StringBuilder();
        for (String[] p : pairs) {
            if (!b.isEmpty()) b.append('&');
            b.append(encode(p[0]));
            if (!p[1].isEmpty()) b.append('=').append(encode(p[1]));
        }
        return b.toString();
    }

    static int effectivePort(URI url) {
        if (url.getPort() > 0) return url.getPort();
        if ("https".equalsIgnoreCase(url.getScheme())) return 443;
        return 80;
    }

    private static String decode(String s) {
        try {
            return URLDecoder.decode(s.replace("+", "%2B"), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return s;
        }
    }

    private static String encode(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8)
                .replace("+", "%20")
                .replace("%2B", "%2B");
    }
}
