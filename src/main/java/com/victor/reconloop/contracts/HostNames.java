package com.victor.reconloop.contracts;

import java.util.Locale;
import java.util.regex.Pattern;

final class HostNames {
    private static final Pattern LABEL = Pattern.compile("^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$");
    private static final Pattern EMAIL = Pattern.compile("^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$");

    private HostNames() {}

    static String canonical(String raw) {
        if (raw == null) return "";
        String s = raw.strip().toLowerCase(Locale.ROOT);
        if (s.endsWith(".")) s = s.substring(0, s.length() - 1);
        if (s.startsWith("http://") || s.startsWith("https://")) {
            int slash = s.indexOf('/', s.indexOf("://") + 3);
            s = slash < 0 ? s.substring(s.indexOf("://") + 3) : s.substring(s.indexOf("://") + 3, slash);
            int colon = s.indexOf(':');
            if (colon > 0) s = s.substring(0, colon);
        }
        if (s.startsWith("*.")) s = "*." + s.substring(2);
        return s;
    }

    static boolean looksLikeEmail(String s) {
        return s != null && EMAIL.matcher(s.strip()).matches();
    }

    static boolean looksLikeUrl(String s) {
        if (s == null) return false;
        String t = s.strip().toLowerCase(Locale.ROOT);
        return t.startsWith("http://") || t.startsWith("https://") || t.startsWith("javascript:")
                || t.startsWith("data:") || t.startsWith("mailto:");
    }

    static String validateFqdn(String raw, boolean allowWildcard) {
        String host = canonical(raw);
        if (host.isEmpty()) return "empty hostname";
        if (looksLikeEmail(raw)) return "looks like an email, not a hostname";
        if (raw != null && (raw.contains("/") || raw.contains(" ") || raw.contains("?"))) {
            return "hostname contains path/query/whitespace";
        }
        boolean wildcard = host.startsWith("*.");
        if (wildcard) {
            if (!allowWildcard) return "wildcard hostnames are not permitted here";
            host = host.substring(2);
            if (host.isEmpty()) return "wildcard without a registrable suffix";
        }
        if (host.length() > 253) return "hostname longer than 253 characters";
        String[] labels = host.split("\\.");
        if (labels.length < 2) return "hostname is not a FQDN";
        for (String label : labels) {
            if (label.isEmpty()) return "empty DNS label";
            if (label.length() > 63) return "DNS label longer than 63 characters";
            if (!LABEL.matcher(label).matches()) return "invalid DNS label '" + label + "'";
        }
        return null;
    }
}
