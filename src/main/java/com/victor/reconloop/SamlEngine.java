package com.victor.reconloop;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.Inflater;

/**
 * Passive SAML request/response heuristics. Decodes a {@code SAMLRequest}/{@code SAMLResponse}
 * parameter (base64, falling back to raw DEFLATE for the HTTP-Redirect binding) and inspects the
 * resulting XML text with targeted regexes rather than a full XML DOM — avoids a new dependency for
 * the handful of signals this looks for. Pure and dependency-free so it's directly unit-testable.
 */
final class SamlEngine {

    record Note(String severity, String name, String detail) {}

    private static final Pattern SIGNATURE = Pattern.compile("<(?:\\w+:)?Signature[\\s>/]");
    private static final Pattern SIGNATURE_METHOD = Pattern.compile(
            "SignatureMethod[^>]*Algorithm=[\"']([^\"']+)[\"']", Pattern.CASE_INSENSITIVE);
    private static final Pattern ASSERTION = Pattern.compile("<(?:\\w+:)?Assertion[\\s>]");
    private static final Pattern NAMEID_FORMAT = Pattern.compile(
            "NameID[^>]*Format=[\"']([^\"']+)[\"']", Pattern.CASE_INSENSITIVE);

    /** Matched against the tail of the SignatureMethod Algorithm URI, case-insensitive. */
    private static final Set<String> WEAK_SIGNATURE_ALGORITHMS = Set.of("rsa-sha1", "dsa-sha1", "hmac-sha1");

    static boolean looksLikeSamlParam(String paramName) {
        if (paramName == null) return false;
        String lower = paramName.toLowerCase(Locale.ROOT);
        return lower.equals("samlresponse") || lower.equals("samlrequest");
    }

    /** Decodes a SAMLRequest/SAMLResponse parameter value and analyzes the resulting XML. */
    static List<Note> analyze(String samlParamValue) {
        List<Note> notes = new ArrayList<>();
        String xml = decode(samlParamValue);
        if (xml == null) return notes;
        analyzeXml(xml, notes);
        return notes;
    }

    /** Pure core over already-decoded XML text, so it's testable without base64/deflate fixtures. */
    static void analyzeXml(String xml, List<Note> notes) {
        if (xml == null || xml.isBlank()) return;

        boolean hasSignature = SIGNATURE.matcher(xml).find();
        int assertionCount = countMatches(ASSERTION, xml);

        if (!hasSignature) {
            notes.add(new Note("HIGH", "Unsigned SAML message",
                    "No XML Signature element was found in the decoded SAML message. Without a signature, an "
                            + "attacker who can reach the assertion consumer service can forge an arbitrary "
                            + "assertion/response (e.g. authenticate as any user)."));
        } else {
            Matcher sigAlg = SIGNATURE_METHOD.matcher(xml);
            while (sigAlg.find()) {
                String alg = sigAlg.group(1).toLowerCase(Locale.ROOT);
                for (String weak : WEAK_SIGNATURE_ALGORITHMS) {
                    if (alg.contains(weak)) {
                        notes.add(new Note("MEDIUM", "Weak SAML signature algorithm",
                                "SignatureMethod uses " + weak.toUpperCase(Locale.ROOT) + " (" + alg + "); "
                                        + "SHA-1-based signatures are deprecated and should be replaced with "
                                        + "SHA-256 or stronger."));
                        break;
                    }
                }
            }
        }

        if (assertionCount > 1) {
            notes.add(new Note("MEDIUM", "Multiple SAML Assertion elements in one message",
                    "The decoded message contains " + assertionCount + " <Assertion> elements. This shape is used "
                            + "by XML Signature Wrapping (XSW) attacks, where an attacker adds a second, unsigned "
                            + "or differently-signed assertion hoping the verifier processes it instead of the "
                            + "signed one. Confirm the service resolves the processed assertion strictly by the "
                            + "signature's reference, not by document position."));
        }

        Matcher nameIdFormat = NAMEID_FORMAT.matcher(xml);
        if (nameIdFormat.find() && !hasSignature) {
            String format = nameIdFormat.group(1);
            if (format.toLowerCase(Locale.ROOT).endsWith("unspecified")) {
                notes.add(new Note("LOW", "Unspecified SAML NameID format on an unsigned message",
                        "NameID Format is 'unspecified' and the message is unsigned; combined, the recipient may "
                                + "accept an attacker-chosen identifier with no cryptographic guarantee of origin."));
            }
        }
    }

    private static int countMatches(Pattern pattern, String text) {
        Matcher m = pattern.matcher(text);
        int n = 0;
        while (m.find()) n++;
        return n;
    }

    /** Base64-decodes, then falls back to raw-DEFLATE (HTTP-Redirect binding) if it isn't already XML. */
    static String decode(String value) {
        if (value == null || value.isBlank()) return null;
        byte[] raw;
        try {
            raw = Base64.getMimeDecoder().decode(value.trim());
        } catch (Exception e) {
            return null;
        }
        if (raw.length == 0) return null;

        // POST binding: plain base64 of UTF-8 XML text. Checking only the (whitespace-skipped) start
        // for '<' matters here — checking "contains '<' anywhere" false-positives on raw DEFLATE-
        // compressed bytes, which are effectively random and can easily contain a stray 0x3C byte.
        if (looksLikeXmlStart(raw)) return new String(raw, StandardCharsets.UTF_8);

        // HTTP-Redirect binding: base64 of raw-DEFLATE-compressed XML.
        String inflated = tryInflate(raw);
        return inflated != null && looksLikeXmlStart(inflated.getBytes(StandardCharsets.UTF_8)) ? inflated : null;
    }

    private static boolean looksLikeXmlStart(byte[] bytes) {
        int i = 0;
        while (i < bytes.length && isXmlWhitespace(bytes[i])) i++;
        return i < bytes.length && bytes[i] == '<';
    }

    private static boolean isXmlWhitespace(byte b) {
        return b == ' ' || b == '\t' || b == '\n' || b == '\r';
    }

    private static String tryInflate(byte[] raw) {
        Inflater inflater = new Inflater(true); // raw DEFLATE, no zlib header
        try {
            // Raw (nowrap) DEFLATE streams have no trailing checksum, so Java's Inflater can withhold
            // the final decompressed block waiting for more input that will never come. The standard
            // workaround (JDK-4795662) is to append one dummy byte, which unblocks the final flush.
            byte[] padded = java.util.Arrays.copyOf(raw, raw.length + 1);
            inflater.setInput(padded);
            ByteArrayOutputStream out = new ByteArrayOutputStream(Math.max(64, raw.length * 4));
            byte[] buffer = new byte[4096];
            while (!inflater.finished()) {
                int n = inflater.inflate(buffer);
                if (n == 0) {
                    if (inflater.needsInput() || inflater.needsDictionary()) break;
                } else {
                    out.write(buffer, 0, n);
                }
            }
            return out.toString(StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        } finally {
            inflater.end();
        }
    }
}
