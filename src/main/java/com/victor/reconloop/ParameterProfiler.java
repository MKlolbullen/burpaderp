package com.victor.reconloop;

import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.*;
import java.util.regex.Pattern;

final class ParameterProfiler {
    record Candidate(String name, String type, String valuePreview, Set<String> classes, int score) {}

    private record Heuristic(String attackClass, Pattern names, int weight) {}

    private static final List<Heuristic> HEURISTICS = List.of(
            h("SQLi", "(?:id|uid|user|account|order|sort|query|search|filter|where|column|table|select|category|product|item|page|offset|limit)", 3),
            h("XSS", "(?:q|query|search|term|keyword|name|title|message|comment|content|html|text|redirect|url|next|return|callback)", 3),
            h("SSTI", "(?:template|view|render|format|theme|layout|email|subject|message|content)", 4),
            h("LFI/path traversal", "(?:file|filename|path|page|include|template|folder|dir|directory|document|download|resource|lang|locale)", 4),
            h("Command/RCE", "(?:cmd|command|exec|execute|run|ping|host|ip|query|code|func|function|process|module|shell|payload)", 5),
            h("SSRF", "(?:url|uri|endpoint|host|domain|callback|webhook|feed|image|avatar|proxy|fetch|remote|target|dest|destination)", 5),
            h("Open redirect", "(?:url|uri|redirect|next|return|returnto|continue|dest|destination|callback|goto|target)", 3),
            h("IDOR/BOLA", "(?:id|uid|user_id|account_id|tenant|org|organization|project|document|invoice|order|uuid)", 3)
    );

    private static Heuristic h(String attackClass, String names, int weight) {
        return new Heuristic(attackClass, Pattern.compile("^(?:" + names + ")$", Pattern.CASE_INSENSITIVE), weight);
    }

    List<Candidate> profile(HttpRequest request) {
        if (request == null || request.parameters() == null) return List.of();
        ArrayList<Candidate> out = new ArrayList<>();
        for (HttpParameter p : request.parameters()) {
            String name = p.name() == null ? "" : p.name();
            LinkedHashSet<String> classes = new LinkedHashSet<>();
            int score = 1;
            for (Heuristic h : HEURISTICS) {
                if (h.names().matcher(name).matches()) {
                    classes.add(h.attackClass());
                    score += h.weight();
                }
            }
            String value = p.value() == null ? "" : p.value();
            if (looksNumeric(value)) { classes.add("numeric mutation"); score++; }
            if (looksJson(value)) { classes.add("structured value"); score += 2; }
            if (looksUrl(value)) { classes.add("URL sink"); score += 3; }
            if (name.isBlank()) continue;
            out.add(new Candidate(name, String.valueOf(p.type()), preview(value), Set.copyOf(classes), score));
        }
        out.sort(Comparator.comparingInt(Candidate::score).reversed());
        return out;
    }

    private static boolean looksNumeric(String s) { return s.matches("-?\\d+(?:\\.\\d+)?"); }
    private static boolean looksJson(String s) { String t = s.trim(); return (t.startsWith("{") && t.endsWith("}")) || (t.startsWith("[") && t.endsWith("]")); }
    private static boolean looksUrl(String s) { return s.matches("(?i)https?://.*") || s.startsWith("//"); }
    private static String preview(String s) { return s.length() <= 120 ? s : s.substring(0, 117) + "..."; }
}
