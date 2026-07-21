package com.victor.reconloop;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class DiscoveryEngine {
    private static final String EXT = InterestingResourceCatalog.extensionAlternation();

    private static final List<Pattern> PATTERNS = List.of(
            Pattern.compile("https?://[^\\s\\\"'<>`)]+", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?:fetch|axios\\.(?:get|post|put|patch|delete|request)|import|require)\\s*\\(\\s*[\\\"']([^\\\"']+)[\\\"']", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?:src|href|action|data-src|data-url|endpoint|url)\\s*=\\s*[\\\"']([^\\\"'#]+)[\\\"']", Pattern.CASE_INSENSITIVE),
            Pattern.compile("[\\\"']((?:/|\\./|\\.\\./)[^\\\"'\\s<>]{1,1600})[\\\"']"),
            Pattern.compile("[\\\"']([^\\\"'\\s<>]+\\.(?:" + EXT + ")(?:[?#][^\\\"']*)?)[\\\"']", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?i)//[#@]?\\s*sourceMappingURL=([^\\s]+)"),
            Pattern.compile("(?i)(?:X-SourceMap|SourceMap):\\s*([^\\r\\n]+)")
    );

    Set<URI> discover(URI base, String text) {
        if (base == null || text == null || text.isBlank()) return Set.of();
        LinkedHashSet<URI> found = new LinkedHashSet<>();

        for (Pattern pattern : PATTERNS) {
            Matcher matcher = pattern.matcher(text);
            while (matcher.find()) {
                String raw = matcher.groupCount() >= 1 && matcher.group(1) != null
                        ? matcher.group(1)
                        : matcher.group();
                URI resolved = resolve(base, clean(raw));
                if (resolved != null && isHttp(resolved)) found.add(normalize(resolved));
            }
        }
        return found;
    }

    Set<URI> parentDirectories(URI uri) {
        LinkedHashSet<URI> out = new LinkedHashSet<>();
        if (uri == null || uri.getPath() == null) return out;
        String path = uri.getPath();
        int lastSlash = path.lastIndexOf('/');
        if (lastSlash < 0) return out;
        String dir = path.substring(0, lastSlash + 1);
        if (dir.isBlank()) dir = "/";

        String[] parts = dir.split("/");
        StringBuilder current = new StringBuilder("/");
        for (String part : parts) {
            if (part.isBlank()) continue;
            current.append(part).append('/');
            try {
                out.add(new URI(uri.getScheme(), uri.getUserInfo(), uri.getHost(), uri.getPort(), current.toString(), null, null));
            } catch (URISyntaxException ignored) {}
        }
        return out;
    }

    URI redirectTarget(URI base, String location) {
        if (base == null || location == null || location.isBlank()) return null;
        return resolve(base, location.trim());
    }

    static boolean sameOrigin(URI a, URI b) {
        if (a == null || b == null) return false;
        return Objects.equals(lower(a.getScheme()), lower(b.getScheme()))
                && Objects.equals(lower(a.getHost()), lower(b.getHost()))
                && effectivePort(a) == effectivePort(b);
    }

    static String origin(URI uri) {
        if (uri == null) return "";
        int port = uri.getPort();
        String defaultPort = ("https".equalsIgnoreCase(uri.getScheme()) && port == 443)
                || ("http".equalsIgnoreCase(uri.getScheme()) && port == 80)
                || port < 0 ? "" : ":" + port;
        return uri.getScheme() + "://" + uri.getHost() + defaultPort;
    }

    private static URI resolve(URI base, String raw) {
        if (raw == null || raw.isBlank()) return null;
        String lower = raw.toLowerCase(Locale.ROOT);
        if (lower.startsWith("javascript:") || lower.startsWith("data:") || lower.startsWith("mailto:") || raw.startsWith("#")) return null;
        try {
            return base.resolve(raw);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private static URI normalize(URI uri) {
        try {
            String path = uri.getPath() == null || uri.getPath().isBlank() ? "/" : uri.getPath();
            return new URI(uri.getScheme(), uri.getUserInfo(), uri.getHost(), uri.getPort(), path, uri.getQuery(), null).normalize();
        } catch (URISyntaxException e) {
            return uri;
        }
    }

    private static String clean(String raw) {
        return raw.replace("&amp;", "&").replace("\\/", "/").trim();
    }

    private static boolean isHttp(URI uri) {
        return "http".equalsIgnoreCase(uri.getScheme()) || "https".equalsIgnoreCase(uri.getScheme());
    }

    private static int effectivePort(URI uri) {
        if (uri.getPort() >= 0) return uri.getPort();
        return "https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80;
    }

    private static String lower(String value) {
        return value == null ? null : value.toLowerCase(Locale.ROOT);
    }
}
