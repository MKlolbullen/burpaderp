package com.victor.reconloop;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Minimal, dependency-free recursive-descent JSON parser (an RFC-8259 subset)
 * returning plain Java objects: {@link Map}&lt;String,Object&gt;, {@link List}&lt;Object&gt;,
 * {@link String}, {@link Double}, {@link Boolean}, or {@code null}.
 *
 * <p>Used to parse structured findings returned by an LLM without pulling in a
 * JSON dependency (the extension ships as a single jar). It is deliberately
 * tolerant of trailing content after the root value and throws
 * {@link IllegalArgumentException} on malformed input so callers can fall back.
 */
final class Json {
    private final String s;
    private int i;

    private Json(String s) { this.s = s; }

    /** Parses the first complete JSON value in {@code text}. */
    static Object parse(String text) {
        Json p = new Json(text == null ? "" : text);
        p.ws();
        Object v = p.value();
        return v;
    }

    /** Parses exactly one complete JSON value, rejecting trailing non-whitespace data. */
    static Object parseStrict(String text) {
        Json p = new Json(text == null ? "" : text);
        p.ws();
        Object v = p.value();
        p.ws();
        if (p.i != p.s.length()) throw p.err("unexpected trailing content");
        return v;
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> asObject(Object o) {
        return o instanceof Map ? (Map<String, Object>) o : null;
    }

    @SuppressWarnings("unchecked")
    static List<Object> asArray(Object o) {
        return o instanceof List ? (List<Object>) o : null;
    }

    /** Returns the value for {@code key} as a trimmed string, or {@code null}. */
    static String str(Map<String, Object> o, String key) {
        if (o == null) return null;
        Object v = o.get(key);
        if (v == null) return null;
        String s = String.valueOf(v);
        return s.strip();
    }

    // ---- serialization + RFC-6901 pointer access (for JSON-body insertion points) ----

    /** Serialises a parsed tree ({@link Map}/{@link List}/String/Number/Boolean/null) back to JSON. */
    static String write(Object value) {
        StringBuilder sb = new StringBuilder();
        writeValue(sb, value);
        return sb.toString();
    }

    private static void writeValue(StringBuilder sb, Object v) {
        if (v == null) { sb.append("null"); return; }
        if (v instanceof String s) { writeString(sb, s); return; }
        if (v instanceof Boolean b) { sb.append(b.booleanValue() ? "true" : "false"); return; }
        if (v instanceof Number n) { writeNumber(sb, n); return; }
        if (v instanceof Map<?, ?> m) {
            sb.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> e : m.entrySet()) {
                if (!first) sb.append(',');
                first = false;
                writeString(sb, String.valueOf(e.getKey()));
                sb.append(':');
                writeValue(sb, e.getValue());
            }
            sb.append('}');
            return;
        }
        if (v instanceof List<?> a) {
            sb.append('[');
            boolean first = true;
            for (Object e : a) {
                if (!first) sb.append(',');
                first = false;
                writeValue(sb, e);
            }
            sb.append(']');
            return;
        }
        writeString(sb, String.valueOf(v)); // fallback: treat anything else as a string
    }

    private static void writeNumber(StringBuilder sb, Number n) {
        if (n instanceof Double d) {
            if (d.isNaN() || d.isInfinite()) { sb.append("null"); return; }
            if (d == Math.rint(d) && Math.abs(d) < 1e15) { sb.append(Long.toString(d.longValue())); return; }
        }
        sb.append(n.toString());
    }

    private static void writeString(StringBuilder sb, String s) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                default -> {
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
                }
            }
        }
        sb.append('"');
    }

    /** RFC-6901 JSON Pointers to every primitive (string/number/boolean) leaf in {@code tree}. */
    static List<String> leafPointers(Object tree) {
        List<String> out = new ArrayList<>();
        collectPointers(tree, new StringBuilder(), out);
        return out;
    }

    private static void collectPointers(Object node, StringBuilder path, List<String> out) {
        if (node instanceof Map<?, ?> m) {
            for (Map.Entry<?, ?> e : m.entrySet()) {
                int len = path.length();
                path.append('/').append(escapeToken(String.valueOf(e.getKey())));
                collectPointers(e.getValue(), path, out);
                path.setLength(len);
            }
        } else if (node instanceof List<?> a) {
            for (int i = 0; i < a.size(); i++) {
                int len = path.length();
                path.append('/').append(i);
                collectPointers(a.get(i), path, out);
                path.setLength(len);
            }
        } else if (node instanceof String || node instanceof Number || node instanceof Boolean) {
            out.add(path.toString()); // a primitive leaf; null/container nodes are not injectable points
        }
    }

    /** Resolves {@code pointer} against {@code tree}, or {@code null} if any step is missing. */
    static Object getByPointer(Object tree, String pointer) {
        Object node = tree;
        for (String token : splitPointer(pointer)) {
            node = step(node, token);
            if (node == null) return null;
        }
        return node;
    }

    /** Sets the leaf {@code pointer} refers to, in place. Returns false if the path can't be resolved. */
    @SuppressWarnings("unchecked")
    static boolean setByPointer(Object tree, String pointer, Object value) {
        List<String> tokens = splitPointer(pointer);
        if (tokens.isEmpty()) return false;
        Object node = tree;
        for (int i = 0; i < tokens.size() - 1; i++) {
            node = step(node, tokens.get(i));
            if (node == null) return false;
        }
        String last = tokens.get(tokens.size() - 1);
        if (node instanceof Map<?, ?> m) {
            String key = unescapeToken(last);
            if (m.containsKey(key)) { ((Map<String, Object>) m).put(key, value); return true; } // replace only
            return false;
        }
        if (node instanceof List<?> a) {
            int idx = parseIndex(last);
            if (idx >= 0 && idx < a.size()) { ((List<Object>) a).set(idx, value); return true; }
        }
        return false;
    }

    private static Object step(Object node, String token) {
        if (node instanceof Map<?, ?> m) return m.get(unescapeToken(token));
        if (node instanceof List<?> a) {
            int idx = parseIndex(token);
            return (idx >= 0 && idx < a.size()) ? a.get(idx) : null;
        }
        return null;
    }

    private static List<String> splitPointer(String pointer) {
        List<String> tokens = new ArrayList<>();
        if (pointer == null || pointer.isEmpty()) return tokens;
        for (String part : pointer.substring(1).split("/", -1)) tokens.add(part);
        return tokens;
    }

    private static int parseIndex(String token) {
        if (token == null || token.isEmpty()) return -1;
        for (int i = 0; i < token.length(); i++) if (!Character.isDigit(token.charAt(i))) return -1;
        try { return Integer.parseInt(token); } catch (NumberFormatException e) { return -1; }
    }

    private static String escapeToken(String token) {
        return token.replace("~", "~0").replace("/", "~1");
    }

    private static String unescapeToken(String token) {
        return token.replace("~1", "/").replace("~0", "~");
    }

    private Object value() {
        char c = peek();
        return switch (c) {
            case '{' -> object();
            case '[' -> array();
            case '"' -> string();
            case 't', 'f' -> bool();
            case 'n' -> nul();
            default -> number();
        };
    }

    private Map<String, Object> object() {
        Map<String, Object> m = new LinkedHashMap<>();
        expect('{');
        ws();
        if (peek() == '}') { i++; return m; }
        while (true) {
            ws();
            String key = string();
            ws();
            expect(':');
            ws();
            m.put(key, value());
            ws();
            char c = next();
            if (c == '}') return m;
            if (c != ',') throw err("expected ',' or '}'");
        }
    }

    private List<Object> array() {
        List<Object> a = new ArrayList<>();
        expect('[');
        ws();
        if (peek() == ']') { i++; return a; }
        while (true) {
            ws();
            a.add(value());
            ws();
            char c = next();
            if (c == ']') return a;
            if (c != ',') throw err("expected ',' or ']'");
        }
    }

    private String string() {
        expect('"');
        StringBuilder b = new StringBuilder();
        while (true) {
            char c = next();
            if (c == '"') return b.toString();
            if (c == '\\') {
                char e = next();
                switch (e) {
                    case '"' -> b.append('"');
                    case '\\' -> b.append('\\');
                    case '/' -> b.append('/');
                    case 'n' -> b.append('\n');
                    case 't' -> b.append('\t');
                    case 'r' -> b.append('\r');
                    case 'b' -> b.append('\b');
                    case 'f' -> b.append('\f');
                    case 'u' -> {
                        if (i + 4 > s.length()) throw err("truncated \\u escape");
                        b.append((char) Integer.parseInt(s.substring(i, i + 4), 16));
                        i += 4;
                    }
                    default -> b.append(e);
                }
            } else {
                b.append(c);
            }
        }
    }

    private Object number() {
        int start = i;
        while (i < s.length() && "+-0123456789.eE".indexOf(s.charAt(i)) >= 0) i++;
        String num = s.substring(start, i);
        if (num.isEmpty()) throw err("invalid value");
        try {
            return Double.parseDouble(num);
        } catch (NumberFormatException e) {
            throw err("invalid number '" + num + "'");
        }
    }

    private Boolean bool() {
        if (s.startsWith("true", i)) { i += 4; return Boolean.TRUE; }
        if (s.startsWith("false", i)) { i += 5; return Boolean.FALSE; }
        throw err("invalid literal");
    }

    private Object nul() {
        if (s.startsWith("null", i)) { i += 4; return null; }
        throw err("invalid literal");
    }

    private void ws() {
        while (i < s.length() && Character.isWhitespace(s.charAt(i))) i++;
    }

    private char peek() {
        if (i >= s.length()) throw err("unexpected end of input");
        return s.charAt(i);
    }

    private char next() {
        if (i >= s.length()) throw err("unexpected end of input");
        return s.charAt(i++);
    }

    private void expect(char c) {
        if (next() != c) throw err("expected '" + c + "'");
    }

    private IllegalArgumentException err(String message) {
        return new IllegalArgumentException("JSON parse error at index " + i + ": " + message);
    }
}
