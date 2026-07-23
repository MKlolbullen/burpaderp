package com.victor.reconloop;

import java.net.URI;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Reconstructs the URLs of lazy-loaded webpack chunks from a bundle's runtime. Modern webpack builds
 * the filename of each async chunk at runtime from a chunk-id → hash map and a filename template
 * (the {@code __webpack_require__.u} / {@code .miniCssF} functions), so the full filenames never
 * appear as string literals and a normal link crawler misses them. This miner extracts the template
 * and map and rebuilds each chunk URL so the crawler can fetch them (more JS/CSS to mine for
 * endpoints, secrets and source maps).
 *
 * <p>Best-effort and non-executing: it matches the common webpack 4/5 concatenation shape
 * {@code "prefix" + id + "sep" + {id:"hash",…}[id] + "suffix"} plus an optional name map. Bundles
 * that don't match simply yield nothing (the generic discovery still catches literal filenames).
 */
final class WebpackMiner {

    // .u = e => "static/js/" + e + "." + {10:"abc",20:"def"}[e] + ".chunk.js"
    // .u = function(e){return "static/js/"+e+"."+{...}[e]+".chunk.js"}
    private static final Pattern U_FUNC = Pattern.compile(
            "\\.(?:u|miniCssF)\\s*=\\s*(?:function\\s*\\(\\s*\\w+\\s*\\)\\s*\\{\\s*return\\s+|\\(?\\s*\\w+\\s*\\)?\\s*=>\\s*)"
            + "\"([^\"]*)\"\\s*\\+\\s*\\w+\\s*\\+\\s*\"([^\"]*)\"\\s*\\+\\s*(\\{[^{}]*\\})\\s*\\[\\s*\\w+\\s*\\]\\s*\\+\\s*\"([^\"]*)\"");

    private static final Pattern MAP_ENTRY = Pattern.compile("(\\d+)\\s*:\\s*\"([^\"]*)\"");

    // __webpack_require__.p = "https://cdn.example.com/assets/"  (public path / base of chunk URLs)
    private static final Pattern PUBLIC_PATH = Pattern.compile("\\.p\\s*=\\s*\"([^\"]*)\"");

    private static final int MAX_CHUNKS = 2000;

    static boolean looksLikeWebpack(String body) {
        if (body == null) return false;
        return body.contains("__webpack_require__") || body.contains("webpackChunk")
                || body.contains(".chunk.js") || body.contains("webpackJsonp");
    }

    /** Returns reconstructed chunk URLs resolved against {@code base} (the bundle's own URL). */
    static Set<URI> reconstruct(URI base, String body) {
        LinkedHashSet<URI> out = new LinkedHashSet<>();
        if (base == null || body == null || body.isBlank()) return out;

        String publicPath = extractPublicPath(body);
        Matcher u = U_FUNC.matcher(body);
        while (u.find() && out.size() < MAX_CHUNKS) {
            String prefix = u.group(1);
            String sep = u.group(2);
            String map = u.group(3);
            String suffix = u.group(4);
            Matcher entry = MAP_ENTRY.matcher(map);
            while (entry.find() && out.size() < MAX_CHUNKS) {
                String id = entry.group(1);
                String hash = entry.group(2);
                String path = publicPath + prefix + id + sep + hash + suffix;
                URI uri = resolve(base, path);
                if (uri != null) out.add(uri);
            }
        }
        return out;
    }

    private static String extractPublicPath(String body) {
        Matcher m = PUBLIC_PATH.matcher(body);
        while (m.find()) {
            String value = m.group(1);
            // Ignore the "auto" sentinel and obvious non-paths; keep "/" and real URLs/paths.
            if (value == null || value.isBlank() || value.equalsIgnoreCase("auto")) continue;
            String lower = value.toLowerCase(Locale.ROOT);
            if (lower.startsWith("http://") || lower.startsWith("https://") || value.startsWith("/")) return value;
        }
        return "";
    }

    private static URI resolve(URI base, String raw) {
        try {
            URI resolved = base.resolve(raw);
            String scheme = resolved.getScheme();
            if (scheme == null) return null;
            scheme = scheme.toLowerCase(Locale.ROOT);
            return ("http".equals(scheme) || "https".equals(scheme)) ? resolved.normalize() : null;
        } catch (Exception e) {
            return null;
        }
    }
}
