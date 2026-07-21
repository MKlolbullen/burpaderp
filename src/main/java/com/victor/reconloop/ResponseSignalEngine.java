package com.victor.reconloop;

import burp.api.montoya.http.message.responses.HttpResponse;
import java.util.*;
import java.util.regex.*;

final class ResponseSignalEngine {
    record Signal(String severity, String name, String value) {}
    private record Rule(String severity, String name, Pattern pattern) {}

    private static final List<Rule> RULES = List.of(
            r("HIGH", "Possible stack trace", "(?i)(?:Traceback \\(most recent call last\\)|Exception in thread|at [a-zA-Z0-9_.$]+\\([A-Za-z0-9_.$]+\\.java:\\d+\\)|System\\.Data\\.SqlClient|Laravel\\\\Framework|Symfony\\\\Component)"),
            r("MEDIUM", "Debug/error disclosure", "(?i)(?:debug\\s*=\\s*true|display_errors\\s*=\\s*on|SQLSTATE\\[|You have an error in your SQL syntax|Warning: .* on line \\d+|Fatal error:|Notice: Undefined)"),
            r("MEDIUM", "Source map reference", "(?i)(?:sourceMappingURL|X-SourceMap|SourceMap)\\s*[:=]\\s*([^\\s]+)"),
            r("MEDIUM", "Internal hostname hint", "(?i)\\b(?:localhost|[a-z0-9-]+\\.(?:internal|local|corp|lan))\\b"),
            r("LOW", "Directory listing", "(?i)<title>Index of /|<h1>Index of /|Directory listing for"),
            r("LOW", "Interesting technology header/body", "(?i)(?:X-Powered-By|Server:|X-AspNet-Version|X-Generator|X-Drupal-Cache)[: ]+[^\\r\\n<]{1,160}")
    );

    private static Rule r(String severity, String name, String regex) {
        return new Rule(severity, name, Pattern.compile(regex, Pattern.MULTILINE));
    }

    List<Signal> analyze(HttpResponse response) {
        if (response == null) return List.of();
        String text = response.toString();
        ArrayList<Signal> out = new ArrayList<>();
        for (Rule rule : RULES) {
            Matcher m = rule.pattern().matcher(text);
            int n = 0;
            while (m.find() && n++ < 20) out.add(new Signal(rule.severity(), rule.name(), trim(m.group())));
        }
        return out;
    }

    private static String trim(String s) { return s.length() <= 240 ? s : s.substring(0, 237) + "..."; }
}
