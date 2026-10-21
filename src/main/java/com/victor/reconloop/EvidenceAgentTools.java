package com.victor.reconloop;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Actual local tools: only immutable, redacted, selected sources are accessible. No ambient I/O. */
final class EvidenceAgentTools {
    enum Tool {
        SOURCE_INDEX("List source IDs, kinds, character counts and SHA-256; arguments: {}."),
        READ_SOURCE("Read a bounded source excerpt; arguments: {source_id:string, start:int, length:int}. Character offsets; length 1–3000."),
        SEARCH_SOURCES("Literal case-insensitive search, at most 12 snippets; arguments: {query:string} (1–128 characters)."),
        COMPARE_SOURCES("Compare two captured texts, lengths/hashes and first differing excerpt; arguments: {left:string, right:string} source IDs."),
        DECODE_EXCERPT("Decode a verbatim source excerpt as text; arguments: {source_id:string, text:string, encoding:base64|url}. At most 2048 input characters; no evaluation."),
        CHECK_EVIDENCE("Check if a quote occurs verbatim in the specified redacted source; arguments: {source_id:string, quote:string}. Presence alone is not exploitability.");
        private final String description;
        Tool(String description) { this.description = description; }
        String description() { return description; }
        String id() { return name().toLowerCase(Locale.ROOT); }
    }
    static final int MAX_OUTPUT = 4000;

    static String execute(AiAnalysis.Snapshot snapshot, Set<Tool> allowed, String name, Map<String, Object> args) {
        Tool tool;
        try { tool = Tool.valueOf(name.toUpperCase(Locale.ROOT)); }
        catch (Exception e) { throw new IllegalArgumentException("Unknown local tool."); }
        if (!tool.id().equals(name) || !allowed.contains(tool)) throw new IllegalArgumentException("Tool is not allowed for this role.");
        if (args == null) throw new IllegalArgumentException("Tool arguments must be an object.");
        String out = switch (tool) {
            case SOURCE_INDEX -> {
                keys(args); StringBuilder index = new StringBuilder();
                for (var s : snapshot.sources()) index.append(s.id()).append(' ').append(s.kind()).append(" chars=")
                        .append(s.text().length()).append(" sha256=").append(AiAnalysis.sha256(s.text())).append('\n');
                yield index.toString();
            }
            case READ_SOURCE -> {
                keys(args, "source_id", "start", "length"); var s = source(snapshot, string(args, "source_id", 12));
                int start = integer(args, "start", 0, s.text().length()), length = integer(args, "length", 1, 3000);
                yield s.id() + " chars " + start + ".." + Math.min(s.text().length(), start + length) + ":\n"
                        + s.text().substring(start, Math.min(s.text().length(), start + length));
            }
            case SEARCH_SOURCES -> {
                keys(args, "query"); String query = string(args, "query", 128);
                StringBuilder hits = new StringBuilder(); int count = 0;
                outer: for (var s : snapshot.sources()) {
                    int at = 0;
                    while ((at = indexOf(s.text(), query, at)) >= 0) {
                        hits.append(s.id()).append(" @").append(at).append(": ")
                                .append(s.text(), Math.max(0, at - 50), Math.min(s.text().length(), at + query.length() + 90)).append('\n');
                        at += query.length(); if (++count == 12) break outer;
                    }
                }
                yield "Literal search; at most 12 hits.\n" + hits;
            }
            case COMPARE_SOURCES -> {
                keys(args, "left", "right"); var left = source(snapshot, string(args, "left", 12));
                var right = source(snapshot, string(args, "right", 12)); int at = 0;
                while (at < Math.min(left.text().length(), right.text().length()) && left.text().charAt(at) == right.text().charAt(at)) at++;
                yield left.id() + " chars=" + left.text().length() + " sha256=" + AiAnalysis.sha256(left.text()) + "\n"
                        + right.id() + " chars=" + right.text().length() + " sha256=" + AiAnalysis.sha256(right.text()) + "\n"
                        + (left.text().equals(right.text()) ? "Identical captured text." : "First difference @" + at + "\nLEFT: "
                        + left.text().substring(Math.max(0, at - 50), Math.min(left.text().length(), at + 500)) + "\nRIGHT: "
                        + right.text().substring(Math.max(0, at - 50), Math.min(right.text().length(), at + 500)))
                        + "\nText comparison only; no behavioral or authorization conclusion.";
            }
            case DECODE_EXCERPT -> {
                keys(args, "source_id", "text", "encoding"); var s = source(snapshot, string(args, "source_id", 12));
                String text = string(args, "text", 2048), encoding = string(args, "encoding", 10);
                if (!s.text().contains(text)) throw new IllegalArgumentException("Decode input must occur in the selected source.");
                String decoded = switch (encoding) {
                    case "base64" -> new String(Base64.getDecoder().decode(text), StandardCharsets.UTF_8);
                    case "url" -> URLDecoder.decode(text.replace("+", "%2B"), StandardCharsets.UTF_8);
                    default -> throw new IllegalArgumentException("Only base64 and url decoding are available.");
                };
                yield "Source " + s.id() + " decoded text (untrusted, not executed):\n" + decoded.replace('\0', ' ');
            }
            case CHECK_EVIDENCE -> {
                keys(args, "source_id", "quote"); var s = source(snapshot, string(args, "source_id", 12));
                String quote = string(args, "quote", 3000);
                yield "Source " + s.id() + "; verbatim_present=" + s.text().contains(quote)
                        + "; exploitability=UNVERIFIED; sha256=" + AiAnalysis.sha256(s.text());
            }
        };
        out = AiAnalysis.redactDerived(out);
        return out.length() <= MAX_OUTPUT ? out : out.substring(0, MAX_OUTPUT - 40) + "\n[local tool output capped]";
    }
    private static AiAnalysis.Source source(AiAnalysis.Snapshot snapshot, String id) {
        return snapshot.sources().stream().filter(s -> s.id().equals(id)).findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Unknown selected source ID."));
    }
    private static int indexOf(String text, String query, int start) {
        for (int i = start; i <= text.length() - query.length(); i++) if (text.regionMatches(true, i, query, 0, query.length())) return i;
        return -1;
    }
    private static void keys(Map<String, Object> args, String... keys) {
        if (!args.keySet().equals(Set.of(keys))) throw new IllegalArgumentException("Unexpected tool arguments.");
    }
    private static String string(Map<String, Object> args, String key, int max) {
        if (!(args.get(key) instanceof String s) || s.isBlank() || s.length() > max) throw new IllegalArgumentException("Invalid tool string argument.");
        return s;
    }
    private static int integer(Map<String, Object> args, String key, int min, int max) {
        if (!(args.get(key) instanceof Number n) || !Double.isFinite(n.doubleValue()) || n.doubleValue() != n.intValue()
                || n.intValue() < min || n.intValue() > max) throw new IllegalArgumentException("Invalid tool range.");
        return n.intValue();
    }
}
