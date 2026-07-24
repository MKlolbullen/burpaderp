package com.victor.reconloop;

import java.net.URI;
import java.util.*;

final class InterestingResourceCatalog {
    private static final Set<String> EXTENSIONS = Set.of(
            "js","mjs","cjs","jsx","ts","tsx","webchunk","chunk","map","wasm",
            "json","jsonl","xml","yaml","yml","toml","ini","conf","config","cfg","properties","env",
            "txt","log","csv","graphql","gql","proto",
            "bak","backup","old","orig","original","save","swp","swo","tmp","temp","copy","disabled","dist",
            "sql","db","sqlite","sqlite3","mdb",
            "pem","key","crt","cer","csr","p12","pfx","jks","keystore",
            "zip","tar","gz","tgz","bz2","xz","7z","rar","jar","war","ear"
    );

    private static final Set<String> BASENAMES = Set.of(
            ".env", ".env.local", ".env.production", ".gitignore", ".npmrc", ".yarnrc",
            "dockerfile", "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml",
            "web.config", "app.config", "application.properties", "application.yml", "application.yaml",
            "settings.py", "config.php", "phpinfo.php", "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
            "composer.json", "composer.lock", "requirements.txt", "pipfile", "gemfile", "go.mod", "cargo.toml",
            "swagger.json", "swagger.yaml", "openapi.json", "openapi.yaml", "robots.txt", "sitemap.xml"
    );

    static boolean interesting(URI uri) {
        if (uri == null || uri.getPath() == null) return false;
        String path = uri.getPath().toLowerCase(Locale.ROOT);
        String name = path.substring(path.lastIndexOf('/') + 1);
        if (BASENAMES.contains(name)) return true;
        int dot = name.lastIndexOf('.');
        return dot >= 0 && dot + 1 < name.length() && EXTENSIONS.contains(name.substring(dot + 1));
    }

    static String classify(URI uri) {
        if (uri == null || uri.getPath() == null) return "resource";
        String path = uri.getPath();
        if (path.endsWith("/")) return "directory";
        String name = path.substring(path.lastIndexOf('/') + 1).toLowerCase(Locale.ROOT);
        int dot = name.lastIndexOf('.');
        if (dot >= 0 && dot + 1 < name.length()) return "file:." + name.substring(dot + 1);
        return BASENAMES.contains(name) ? "interesting-file" : "endpoint";
    }

    static String extensionAlternation() {
        ArrayList<String> values = new ArrayList<>(EXTENSIONS);
        values.sort(Comparator.comparingInt(String::length).reversed());
        return String.join("|", values);
    }

    /** Distinctive path fragments for known debug/administration tooling (framework consoles, ops
     *  endpoints, VCS metadata) — reachability alone is worth flagging regardless of response content. */
    private static final Set<String> DEBUG_TOOL_PATH_HINTS = Set.of(
            "actuator", "heapdump", "jolokia", "phpinfo.php", "_profiler", "server-status", "server-info",
            "jmx-console", "manager/html", "adminer", "phpmyadmin", "wp-login.php", "xmlrpc.php",
            "/.git/head", "/.git/config");

    /** Path *segments* (matched whole, not substring) that suggest admin/internal-only functionality —
     *  a BFLA lead, not a confirmed exposure, so kept separate from {@link #DEBUG_TOOL_PATH_HINTS}. */
    private static final Set<String> PRIVILEGED_PATH_SEGMENTS = Set.of(
            "admin", "administrator", "internal", "backend", "manage", "management", "console",
            "superuser", "sysadmin", "wp-admin");

    static boolean looksLikeDebugTool(URI uri) {
        if (uri == null || uri.getPath() == null) return false;
        String path = uri.getPath().toLowerCase(Locale.ROOT);
        for (String hint : DEBUG_TOOL_PATH_HINTS) if (path.contains(hint)) return true;
        return false;
    }

    static boolean looksLikePrivilegedPath(URI uri) {
        if (uri == null || uri.getPath() == null) return false;
        String path = uri.getPath().toLowerCase(Locale.ROOT);
        for (String segment : path.split("/")) {
            if (PRIVILEGED_PATH_SEGMENTS.contains(segment)) return true;
        }
        return false;
    }
}
