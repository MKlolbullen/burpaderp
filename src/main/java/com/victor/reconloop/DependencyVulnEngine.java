package com.victor.reconloop;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Lightweight software-composition analysis (SCA) for client-side JavaScript libraries: a curated,
 * dependency-free database of well-known vulnerable front-end libraries, matched by version against
 * script URLs and inline bundle content (banners / version constants). Positive matches are reported
 * as native Burp issues with the associated advisory reference.
 *
 * <p>Heuristic by nature (version strings can be ambiguous in minified bundles), so findings are
 * filed at the rule's severity but should be treated as leads to confirm.
 */
final class DependencyVulnEngine {

    record LibIssue(String library, String version, String severity, String reference, String detail) {}

    private record Rule(String library, Pattern versionPattern, String fixedIn, String severity,
                        String reference, String note) {}

    // "fixedIn" is the first non-vulnerable version; a detected version strictly below it is flagged.
    // Use "99999" to always flag any matched version (e.g. an end-of-life major line).
    private static final List<Rule> RULES = List.of(
            new Rule("jQuery",
                    Pattern.compile("(?i)jquery(?:[.\\-]|[^0-9a-z]{0,8}v?)(\\d+\\.\\d+(?:\\.\\d+)?)"),
                    "3.5.0", "MEDIUM", "CVE-2020-11022 / CVE-2020-11023",
                    "jQuery before 3.5.0 is vulnerable to XSS via HTML containing self-closing tags passed to DOM-manipulation methods."),
            new Rule("AngularJS",
                    Pattern.compile("(?i)angular(?:js)?(?:[.\\-]|[^0-9a-z]{0,8}v?)(1\\.\\d+(?:\\.\\d+)?)"),
                    "99999", "MEDIUM", "AngularJS 1.x (end-of-life)",
                    "AngularJS 1.x is end-of-life and unpatched, with multiple sandbox-escape and XSS issues; migrate off it."),
            new Rule("Lodash",
                    Pattern.compile("(?i)lodash(?:[.\\-]|[^0-9a-z]{0,8}v?)(\\d+\\.\\d+(?:\\.\\d+)?)"),
                    "4.17.21", "MEDIUM", "CVE-2019-10744 / CVE-2020-8203",
                    "Lodash before 4.17.21 is vulnerable to prototype pollution."),
            new Rule("Moment.js",
                    Pattern.compile("(?i)moment(?:[.\\-]|[^0-9a-z]{0,8}v?)(\\d+\\.\\d+(?:\\.\\d+)?)"),
                    "2.29.4", "MEDIUM", "CVE-2022-24785 / CVE-2022-31129",
                    "Moment.js before 2.29.4 is vulnerable to path traversal and ReDoS."),
            new Rule("Handlebars",
                    Pattern.compile("(?i)handlebars(?:[.\\-]|[^0-9a-z]{0,8}v?)(\\d+\\.\\d+(?:\\.\\d+)?)"),
                    "4.7.7", "HIGH", "CVE-2019-19919 / CVE-2021-23369",
                    "Handlebars before 4.7.7 is vulnerable to prototype pollution leading to remote code execution in some setups."),
            new Rule("DOMPurify",
                    Pattern.compile("(?i)dompurify(?:[.\\-]|[^0-9a-z]{0,8}v?)(\\d+\\.\\d+(?:\\.\\d+)?)"),
                    "3.2.4", "MEDIUM", "CVE-2024-45801 / CVE-2024-47875 and earlier mXSS bypasses",
                    "DOMPurify before 3.2.4 has known mutation-XSS sanitizer bypasses."),
            new Rule("Bootstrap",
                    Pattern.compile("(?i)bootstrap(?:[.\\-]|[^0-9a-z]{0,8}v?)(\\d+\\.\\d+(?:\\.\\d+)?)"),
                    "4.3.1", "LOW", "CVE-2019-8331",
                    "Bootstrap before 4.3.1 (and before 3.4.1 on the 3.x line) has XSS in data-* tooltip/popover attributes — verify the branch."),
            new Rule("axios",
                    Pattern.compile("(?i)axios(?:[.\\-]|[^0-9a-z]{0,8}v?)(\\d+\\.\\d+(?:\\.\\d+)?)"),
                    "1.8.2", "HIGH", "CVE-2024-28849 / CVE-2025-27152",
                    "axios before 1.8.2 leaks credentials on cross-origin redirects and allows SSRF / absolute-URL bypass."),
            new Rule("Next.js",
                    Pattern.compile("(?i)\\bnext(?:\\.?js)?[^0-9]{1,6}(\\d+\\.\\d+\\.\\d+)\\b"),
                    "15.2.3", "HIGH", "CVE-2025-29927",
                    "Next.js before 15.2.3 (and the 14.x line before 14.2.25) allows authorization bypass via a crafted x-middleware-subrequest header."),
            new Rule("jQuery UI",
                    Pattern.compile("(?i)jquery[.\\-]?ui(?:[.\\-]|[^0-9a-z]{0,8}v?)(\\d+\\.\\d+(?:\\.\\d+)?)"),
                    "1.13.2", "MEDIUM", "CVE-2022-31160",
                    "jQuery UI before 1.13.2 has XSS via the checkboxradio widget's label HTML."),
            new Rule("marked",
                    Pattern.compile("(?i)\\bmarked(?:[.\\-]|[^0-9a-z]{0,6}v?)(\\d+\\.\\d+\\.\\d+)\\b"),
                    "4.0.10", "MEDIUM", "CVE-2022-21680 / CVE-2022-21681",
                    "marked before 4.0.10 is vulnerable to ReDoS in its block/inline grammar."),
            new Rule("sanitize-html",
                    Pattern.compile("(?i)sanitize-html(?:[.\\-]|[^0-9a-z]{0,8}v?)(\\d+\\.\\d+(?:\\.\\d+)?)"),
                    "2.7.1", "MEDIUM", "CVE-2022-25887",
                    "sanitize-html before 2.7.1 is vulnerable to ReDoS and sanitization bypass."),
            new Rule("Underscore.js",
                    Pattern.compile("(?i)underscore(?:[.\\-]|[^0-9a-z]{0,8}v?)(\\d+\\.\\d+\\.\\d+)"),
                    "1.12.1", "HIGH", "CVE-2021-23358",
                    "Underscore before 1.12.1 allows arbitrary code execution via the template function."),
            new Rule("PrismJS",
                    Pattern.compile("(?i)prism(?:js)?(?:[.\\-]|[^0-9a-z]{0,8}v?)(\\d+\\.\\d+(?:\\.\\d+)?)"),
                    "1.27.0", "MEDIUM", "CVE-2022-23647",
                    "PrismJS before 1.27.0 has DOM XSS via crafted markup in highlighted code.")
    );

    List<LibIssue> scan(String url, String body) {
        List<LibIssue> issues = new ArrayList<>();
        String haystack = (url == null ? "" : url) + "\n" + (body == null ? "" : body);
        if (haystack.isBlank()) return issues;
        for (Rule rule : RULES) {
            String version = firstVersion(rule.versionPattern(), haystack);
            if (version == null) continue;
            if (isVulnerable(version, rule.fixedIn())) {
                String detail = rule.library() + " " + version + " — " + rule.note()
                        + " (fixed in " + ("99999".equals(rule.fixedIn()) ? "n/a" : rule.fixedIn()) + ").";
                issues.add(new LibIssue(rule.library(), version, rule.severity(), rule.reference(), detail));
            }
        }
        return issues;
    }

    private static String firstVersion(Pattern pattern, String haystack) {
        Matcher m = pattern.matcher(haystack);
        return m.find() ? m.group(1) : null;
    }

    /** True if {@code version} is strictly below {@code fixedIn} ("99999" always returns true). */
    static boolean isVulnerable(String version, String fixedIn) {
        if ("99999".equals(fixedIn)) return true;
        return compareVersions(version, fixedIn) < 0;
    }

    static int compareVersions(String a, String b) {
        String[] pa = a.split("\\.");
        String[] pb = b.split("\\.");
        int n = Math.max(pa.length, pb.length);
        for (int i = 0; i < n; i++) {
            int va = i < pa.length ? parse(pa[i]) : 0;
            int vb = i < pb.length ? parse(pb[i]) : 0;
            if (va != vb) return Integer.compare(va, vb);
        }
        return 0;
    }

    private static int parse(String segment) {
        StringBuilder digits = new StringBuilder();
        for (int i = 0; i < segment.length(); i++) {
            char c = segment.charAt(i);
            if (Character.isDigit(c)) digits.append(c);
            else break;
        }
        return digits.isEmpty() ? 0 : Integer.parseInt(digits.toString());
    }
}
