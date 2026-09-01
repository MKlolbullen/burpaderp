package com.victor.reconloop;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Strict Java representation of the public JSONL records emitted by the Go recon sidecar.
 *
 * <p>The sidecar already validates its own contracts; this parser intentionally validates again at
 * the Java boundary.  A JSONL file is an untrusted interchange artifact, not a capability to add
 * assets or issues to a Burp project without checks.
 */
final class SidecarEvent {
    enum Kind {
        DOMAIN,
        HOSTNAME,
        RESOLVED_HOST,
        IP,
        CIDR,
        SERVICE,
        HTTP_TARGET,
        URL,
        PARAMETERIZED_URL,
        PAYLOAD,
        FINDING;

        static Kind fromWire(String value) {
            if (value == null) throw new IllegalArgumentException("record kind is required");
            try {
                return Kind.valueOf(value.strip().toUpperCase(Locale.ROOT));
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException("unsupported sidecar record kind: " + value);
            }
        }
    }

    record Event(Kind kind, String value, String hostname, List<String> addresses, List<String> cnames,
                 String ip, String cidr, int port, String protocol, String url, int status,
                 String parameter, String tool, String severity, String evidence, String source,
                 String runId, boolean derived) {
        Event {
            addresses = addresses == null ? List.of() : List.copyOf(addresses);
            cnames = cnames == null ? List.of() : List.copyOf(cnames);
        }

        /** Types that have a safe, meaningful Burp-side materialisation today. */
        boolean materializable() {
            return kind != Kind.PAYLOAD && kind != Kind.CIDR;
        }

        /** Candidate scope URLs checked again by the Burp control plane before import. */
        List<String> scopeCandidates() {
            if (url != null && !url.isBlank()) return List.of(url);
            String host = hostname;
            if ((host == null || host.isBlank()) && ip != null && !ip.isBlank()) host = ip;
            if (host == null || host.isBlank()) return List.of();
            String bracketed = host.contains(":") && !host.startsWith("[") ? "[" + host + "]" : host;
            if (kind == Kind.SERVICE && port > 0) {
                return List.of("https://" + bracketed + ":" + port + "/", "http://" + bracketed + ":" + port + "/");
            }
            return List.of("https://" + bracketed + "/", "http://" + bracketed + "/");
        }
    }

    private static final int MAX_URL = 8 << 10;
    private static final int MAX_EVIDENCE = 64 << 10;
    private static final int MAX_TEXT = 512;

    private SidecarEvent() {}

    static Event parse(String jsonLine) {
        Map<String, Object> object = Json.asObject(Json.parse(jsonLine));
        if (object == null) throw new IllegalArgumentException("sidecar line must be a JSON object");
        Kind kind = Kind.fromWire(text(object, "kind", 64, true));
        String value = text(object, "value", MAX_URL, false);
        String hostname = text(object, "hostname", 253, false);
        String ip = text(object, "ip", 128, false);
        String cidr = text(object, "cidr", 128, false);
        String url = text(object, "url", MAX_URL, false);
        String parameter = text(object, "parameter", MAX_TEXT, false);
        String tool = text(object, "tool", MAX_TEXT, false);
        String declaredTool = tool;
        String severity = text(object, "severity", 32, false);
        String evidence = text(object, "evidence", MAX_EVIDENCE, false);
        String source = text(object, "source", MAX_TEXT, false);
        String runId = text(object, "run_id", 128, false);
        String protocol = text(object, "protocol", 16, false);
        int port = integer(object, "port");
        int status = integer(object, "status");
        boolean derived = Boolean.TRUE.equals(object.get("derived"));
        List<String> addresses = strings(object.get("addresses"), "addresses");
        List<String> cnames = strings(object.get("cnames"), "cnames");

        for (String address : addresses) {
            if (!isIpLiteral(address)) throw new IllegalArgumentException("invalid resolved address");
        }
        List<String> normalizedCnames = new ArrayList<>();
        for (String cname : cnames) normalizedCnames.add(normalizeHostname(cname));
        cnames = List.copyOf(normalizedCnames);

        ip = firstNonBlank(ip, kind == Kind.IP ? value : null);
        hostname = normalizeHostname(firstNonBlank(hostname, kind == Kind.DOMAIN || kind == Kind.HOSTNAME
                || kind == Kind.RESOLVED_HOST ? value : null));
        url = firstNonBlank(url, kind == Kind.HTTP_TARGET || kind == Kind.URL || kind == Kind.PARAMETERIZED_URL
                || kind == Kind.FINDING ? value : null);
        if (url != null) url = normalizeHttpUrl(url);
        if (tool == null || tool.isBlank()) tool = "unknown";
        if (source == null || source.isBlank()) source = tool;
        if (severity == null || severity.isBlank()) severity = "info";
        severity = severity.toLowerCase(Locale.ROOT);
        if (!List.of("critical", "high", "medium", "low", "info", "information").contains(severity)) {
            throw new IllegalArgumentException("unsupported finding severity: " + severity);
        }

        switch (kind) {
            case DOMAIN, HOSTNAME -> require(hostname != null, kind.name().toLowerCase(Locale.ROOT) + " requires hostname/value");
            case RESOLVED_HOST -> {
                require(hostname != null, "resolved_host requires hostname/value");
                require(!addresses.isEmpty() || !cnames.isEmpty(), "resolved_host requires addresses or CNAMEs");
            }
            case IP -> require(isIpLiteral(firstNonBlank(ip, value)), "ip requires a literal IP value");
            case CIDR -> require(cidr != null || value != null, "cidr requires a value");
            case SERVICE -> {
                require(ip != null || hostname != null, "service requires IP or hostname");
                require(port >= 1 && port <= 65535, "service port must be 1..65535");
            }
            case HTTP_TARGET, URL -> require(url != null, kind.name().toLowerCase(Locale.ROOT) + " requires an HTTP(S) URL");
            case PARAMETERIZED_URL -> {
                require(url != null, "parameterized_url requires an HTTP(S) URL");
                require(parameter != null && !parameter.isBlank(), "parameterized_url requires a parameter name");
            }
            case PAYLOAD -> require(value != null && !value.isBlank(), "payload requires a value");
            case FINDING -> {
                require(url != null, "finding target must be an HTTP(S) URL");
                require(declaredTool != null && !declaredTool.isBlank(), "finding requires a tool");
            }
        }
        if (ip != null && !ip.isBlank() && !isIpLiteral(ip)) throw new IllegalArgumentException("invalid literal IP");
        return new Event(kind, value, hostname, addresses, cnames, ip, cidr, port, protocol,
                url, status, parameter, tool, severity, evidence, source, runId, derived);
    }

    private static String normalizeHostname(String value) {
        if (value == null || value.isBlank()) return null;
        String host = value.strip().toLowerCase(Locale.ROOT);
        if (host.endsWith(".")) host = host.substring(0, host.length() - 1);
        if (host.length() > 253 || !host.contains(".") || !host.matches("[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?")) {
            throw new IllegalArgumentException("invalid hostname");
        }
        return host;
    }

    private static String normalizeHttpUrl(String raw) {
        try {
            URI uri = URI.create(raw.strip());
            if (uri.getUserInfo() != null || uri.getHost() == null || uri.getHost().isBlank()
                    || !("http".equalsIgnoreCase(uri.getScheme()) || "https".equalsIgnoreCase(uri.getScheme()))) {
                throw new IllegalArgumentException("URL must be absolute HTTP(S) without userinfo");
            }
            return uri.normalize().toString();
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("invalid HTTP(S) URL");
        }
    }

    private static boolean isIpLiteral(String value) {
        if (value == null || value.isBlank()) return false;
        String host = value.strip();
        if (host.startsWith("[") && host.endsWith("]")) host = host.substring(1, host.length() - 1);
        if (host.indexOf(':') >= 0) return host.matches("[0-9a-fA-F:.]+") && !host.equals(":");
        String[] parts = host.split("\\.", -1);
        if (parts.length != 4) return false;
        for (String part : parts) {
            try {
                if (part.isEmpty() || (part.length() > 1 && part.startsWith("0"))) return false;
                int octet = Integer.parseInt(part);
                if (octet < 0 || octet > 255) return false;
            } catch (NumberFormatException e) {
                return false;
            }
        }
        return true;
    }

    private static int integer(Map<String, Object> object, String key) {
        Object value = object.get(key);
        if (value == null) return 0;
        if (value instanceof Number number) {
            double numeric = number.doubleValue();
            if (numeric != Math.rint(numeric) || numeric > Integer.MAX_VALUE || numeric < Integer.MIN_VALUE) {
                throw new IllegalArgumentException(key + " must be an integer");
            }
            return number.intValue();
        }
        try { return Integer.parseInt(String.valueOf(value).strip()); }
        catch (NumberFormatException e) { throw new IllegalArgumentException(key + " must be an integer"); }
    }

    private static List<String> strings(Object value, String field) {
        if (value == null) return List.of();
        List<Object> values = Json.asArray(value);
        if (values == null) throw new IllegalArgumentException(field + " must be an array");
        if (values.size() > 1024) throw new IllegalArgumentException(field + " has too many values");
        List<String> out = new ArrayList<>();
        for (Object item : values) {
            String text = String.valueOf(item).strip();
            if (text.isEmpty() || text.length() > 253) throw new IllegalArgumentException("invalid " + field + " value");
            out.add(text);
        }
        return List.copyOf(out);
    }

    private static String text(Map<String, Object> object, String key, int maxLength, boolean required) {
        String value = Json.str(object, key);
        if (value == null || value.isBlank()) {
            if (required) throw new IllegalArgumentException(key + " is required");
            return null;
        }
        if (value.length() > maxLength) throw new IllegalArgumentException(key + " exceeds " + maxLength + " characters");
        return value;
    }

    private static String firstNonBlank(String first, String second) {
        return first != null && !first.isBlank() ? first : (second != null && !second.isBlank() ? second : null);
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new IllegalArgumentException(message);
    }
}
