package com.victor.reconloop;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Heuristic DOM-XSS source→sink detection for JavaScript. Rather than full dataflow analysis, it
 * flags statements where a known taint SOURCE (URL fragment/query, referrer, {@code window.name},
 * {@code postMessage} data, cookies) appears in the value assigned to, or passed into, a dangerous
 * SINK ({@code innerHTML}, {@code document.write}, {@code eval}, {@code .html()}, {@code src}, …).
 * That co-occurrence in one statement is a strong lead for client-side XSS. Pure and dependency-free.
 */
final class DomXssEngine {

    record DomFinding(String sink, String source, String snippet, int start, int end) {}

    // User-controllable inputs that commonly reach a sink unsanitised.
    private static final Pattern SOURCE = Pattern.compile(
            "location\\.(?:hash|search|href|pathname)"
            + "|document\\.(?:URL|documentURI|referrer|cookie|baseURI)"
            + "|window\\.name"
            + "|\\bevent\\.data\\b"
            + "|\\.data\\.hash\\b");

    // Assignment sinks: capture the right-hand side up to the statement end.
    private static final List<Pattern> ASSIGN_SINKS = List.of(
            Pattern.compile("(\\.(?:innerHTML|outerHTML))\\s*=\\s*([^;\\n]{0,240})"),
            Pattern.compile("(\\.(?:src|href|action))\\s*=\\s*([^;\\n]{0,240})"));

    // Call sinks: capture the first argument region.
    private static final List<Pattern> CALL_SINKS = List.of(
            Pattern.compile("((?:document\\.write(?:ln)?|eval|setTimeout|setInterval|Function"
                    + "|insertAdjacentHTML|\\.html|\\.append|\\.after|\\.before))\\s*\\(\\s*([^)]{0,240})"));

    static List<DomFinding> analyze(String body) {
        List<DomFinding> out = new ArrayList<>();
        if (body == null || body.isBlank()) return out;
        Set<String> seen = new HashSet<>();
        List<Pattern> sinks = new ArrayList<>(ASSIGN_SINKS);
        sinks.addAll(CALL_SINKS);
        for (Pattern sink : sinks) {
            Matcher matcher = sink.matcher(body);
            while (matcher.find()) {
                String sinkName = matcher.group(1).trim();
                String region = matcher.group(2);
                Matcher source = SOURCE.matcher(region);
                if (!source.find()) continue;
                String snippet = (sinkName + " ⇐ " + region).strip();
                if (snippet.length() > 180) snippet = snippet.substring(0, 177) + "...";
                if (seen.add(sinkName + "\0" + source.group() + "\0" + snippet)) {
                    out.add(new DomFinding(sinkName.replaceFirst("^\\.", ""), source.group(), snippet,
                            matcher.start(), matcher.end()));
                }
            }
        }
        return out;
    }
}
