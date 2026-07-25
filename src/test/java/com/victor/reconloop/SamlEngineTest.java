package com.victor.reconloop;

import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.zip.Deflater;

import static org.junit.Assert.*;

public class SamlEngineTest {

    private static boolean hasNote(List<SamlEngine.Note> notes, String nameContains) {
        return notes.stream().anyMatch(n -> n.name().toLowerCase().contains(nameContains.toLowerCase()));
    }

    private static String signedResponse(String signatureAlgorithm, int assertionCount, String nameIdFormat) {
        StringBuilder assertions = new StringBuilder();
        for (int i = 0; i < assertionCount; i++) {
            assertions.append("<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">")
                    .append("<saml:Subject><saml:NameID Format=\"").append(nameIdFormat).append("\">bob</saml:NameID></saml:Subject>")
                    .append("</saml:Assertion>");
        }
        String signature = signatureAlgorithm == null ? "" :
                "<ds:Signature><ds:SignedInfo><ds:SignatureMethod Algorithm=\"" + signatureAlgorithm + "\"/></ds:SignedInfo></ds:Signature>";
        return "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\">" + signature + assertions + "</samlp:Response>";
    }

    private static final String SHA256_ALG = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    private static final String SHA1_ALG = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";

    // ---- looksLikeSamlParam ----

    @Test
    public void recognisesSamlResponseAndRequestParamNamesCaseInsensitively() {
        assertTrue(SamlEngine.looksLikeSamlParam("SAMLResponse"));
        assertTrue(SamlEngine.looksLikeSamlParam("samlresponse"));
        assertTrue(SamlEngine.looksLikeSamlParam("SAMLRequest"));
        assertFalse(SamlEngine.looksLikeSamlParam("SAMLart"));
        assertFalse(SamlEngine.looksLikeSamlParam(null));
    }

    // ---- decode(): base64 (POST binding) and base64+raw-DEFLATE (Redirect binding) ----

    @Test
    public void decodesPlainBase64PostBindingMessage() {
        String xml = signedResponse(SHA256_ALG, 1, "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent");
        String encoded = Base64.getEncoder().encodeToString(xml.getBytes(StandardCharsets.UTF_8));

        assertEquals(xml, SamlEngine.decode(encoded));
    }

    @Test
    public void decodesDeflatedRedirectBindingMessage() throws Exception {
        String xml = signedResponse(SHA256_ALG, 1, "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent");
        String encoded = deflateThenBase64(xml);

        assertEquals(xml, SamlEngine.decode(encoded));
    }

    @Test
    public void decodeReturnsNullForGarbageInput() {
        assertNull(SamlEngine.decode("not valid base64 at all !!!"));
        assertNull(SamlEngine.decode(Base64.getEncoder().encodeToString(new byte[]{1, 2, 3, 4, 5})));
    }

    @Test
    public void decodeReturnsNullForBlankOrNullInput() {
        assertNull(SamlEngine.decode(null));
        assertNull(SamlEngine.decode(""));
        assertNull(SamlEngine.decode("   "));
    }

    private static String deflateThenBase64(String xml) throws Exception {
        Deflater deflater = new Deflater(Deflater.DEFAULT_COMPRESSION, true);
        deflater.setInput(xml.getBytes(StandardCharsets.UTF_8));
        deflater.finish();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[4096];
        while (!deflater.finished()) {
            int n = deflater.deflate(buffer);
            out.write(buffer, 0, n);
        }
        deflater.end();
        return Base64.getEncoder().encodeToString(out.toByteArray());
    }

    // ---- analyzeXml(): the pure signal-detection core ----

    @Test
    public void unsignedMessageIsFlaggedHigh() {
        List<SamlEngine.Note> notes = new java.util.ArrayList<>();
        SamlEngine.analyzeXml(signedResponse(null, 1, "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"), notes);

        SamlEngine.Note note = notes.stream().filter(n -> n.name().toLowerCase().contains("unsigned")).findFirst().orElseThrow();
        assertEquals("HIGH", note.severity());
    }

    @Test
    public void signedMessageIsNotFlaggedAsUnsigned() {
        List<SamlEngine.Note> notes = new java.util.ArrayList<>();
        SamlEngine.analyzeXml(signedResponse(SHA256_ALG, 1, "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"), notes);

        assertFalse(hasNote(notes, "unsigned"));
    }

    @Test
    public void weakSha1SignatureAlgorithmIsFlagged() {
        List<SamlEngine.Note> notes = new java.util.ArrayList<>();
        SamlEngine.analyzeXml(signedResponse(SHA1_ALG, 1, "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"), notes);

        SamlEngine.Note note = notes.stream().filter(n -> n.name().toLowerCase().contains("weak")).findFirst().orElseThrow();
        assertEquals("MEDIUM", note.severity());
    }

    @Test
    public void strongSha256SignatureAlgorithmIsNotFlaggedAsWeak() {
        List<SamlEngine.Note> notes = new java.util.ArrayList<>();
        SamlEngine.analyzeXml(signedResponse(SHA256_ALG, 1, "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"), notes);

        assertFalse(hasNote(notes, "weak"));
    }

    @Test
    public void multipleAssertionsAreFlaggedAsXswSignal() {
        List<SamlEngine.Note> notes = new java.util.ArrayList<>();
        SamlEngine.analyzeXml(signedResponse(SHA256_ALG, 2, "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"), notes);

        assertTrue(hasNote(notes, "multiple saml assertion"));
    }

    @Test
    public void singleAssertionIsNotFlaggedForXsw() {
        List<SamlEngine.Note> notes = new java.util.ArrayList<>();
        SamlEngine.analyzeXml(signedResponse(SHA256_ALG, 1, "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"), notes);

        assertFalse(hasNote(notes, "multiple saml assertion"));
    }

    @Test
    public void unspecifiedNameIdOnUnsignedMessageIsFlagged() {
        List<SamlEngine.Note> notes = new java.util.ArrayList<>();
        SamlEngine.analyzeXml(signedResponse(null, 1, "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"), notes);

        assertTrue(hasNote(notes, "unspecified"));
    }

    @Test
    public void unspecifiedNameIdOnASignedMessageIsNotFlagged() {
        List<SamlEngine.Note> notes = new java.util.ArrayList<>();
        SamlEngine.analyzeXml(signedResponse(SHA256_ALG, 1, "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"), notes);

        assertFalse(hasNote(notes, "unspecified"));
    }

    @Test
    public void blankOrNullXmlProducesNoNotes() {
        List<SamlEngine.Note> notes = new java.util.ArrayList<>();
        SamlEngine.analyzeXml(null, notes);
        SamlEngine.analyzeXml("", notes);
        SamlEngine.analyzeXml("   ", notes);
        assertTrue(notes.isEmpty());
    }

    // ---- analyze(): end-to-end decode + analyze ----

    @Test
    public void endToEndAnalyzeFindsUnsignedMessageThroughBase64() {
        String xml = signedResponse(null, 1, "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent");
        String encoded = Base64.getEncoder().encodeToString(xml.getBytes(StandardCharsets.UTF_8));

        assertTrue(hasNote(SamlEngine.analyze(encoded), "unsigned"));
    }

    @Test
    public void endToEndAnalyzeReturnsEmptyForNonSamlValue() {
        assertTrue(SamlEngine.analyze("dGhpcyBpcyBub3QgWE1M").isEmpty()); // base64 of "this is not XML"
    }
}
