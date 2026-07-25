package com.victor.reconloop;

import org.junit.Test;

import java.util.List;
import java.util.Optional;

import static org.junit.Assert.*;

public class FileUploadEngineTest {

    private static final String BOUNDARY = "----WebKitFormBoundaryXXXX";

    private static String multipartBody(String partName, String filename, String contentType) {
        return "------WebKitFormBoundaryXXXX\r\n"
                + "Content-Disposition: form-data; name=\"" + partName + "\"; filename=\"" + filename + "\"\r\n"
                + "Content-Type: " + contentType + "\r\n\r\n"
                + "<binary file bytes>\r\n"
                + "------WebKitFormBoundaryXXXX--\r\n";
    }

    // ---- looksLikeMultipartFileUpload ----

    @Test
    public void recognisesMultipartFormDataContentType() {
        assertTrue(FileUploadEngine.looksLikeMultipartFileUpload("multipart/form-data; boundary=----WebKitFormBoundaryXXXX"));
        assertFalse(FileUploadEngine.looksLikeMultipartFileUpload("application/json"));
        assertFalse(FileUploadEngine.looksLikeMultipartFileUpload(null));
    }

    // ---- extractBoundary ----

    @Test
    public void extractsUnquotedBoundary() {
        assertEquals(BOUNDARY, FileUploadEngine.extractBoundary("multipart/form-data; boundary=" + BOUNDARY));
    }

    @Test
    public void extractsQuotedBoundary() {
        assertEquals(BOUNDARY, FileUploadEngine.extractBoundary("multipart/form-data; boundary=\"" + BOUNDARY + "\""));
    }

    @Test
    public void returnsNullWhenNoBoundaryPresent() {
        assertNull(FileUploadEngine.extractBoundary("multipart/form-data"));
        assertNull(FileUploadEngine.extractBoundary(null));
    }

    // ---- extractUploadedFiles ----

    @Test
    public void extractsFilenameAndContentTypeFromAFilePart() {
        String body = multipartBody("avatar", "photo.jpg", "image/jpeg");
        List<FileUploadEngine.UploadedFile> files = FileUploadEngine.extractUploadedFiles(body, BOUNDARY);
        assertEquals(1, files.size());
        assertEquals("avatar", files.get(0).partName());
        assertEquals("photo.jpg", files.get(0).filename());
        assertEquals("image/jpeg", files.get(0).declaredContentType());
    }

    @Test
    public void ignoresPartsWithoutAFilenameAttribute() {
        String body = "------WebKitFormBoundaryXXXX\r\n"
                + "Content-Disposition: form-data; name=\"description\"\r\n\r\n"
                + "a plain text field\r\n"
                + "------WebKitFormBoundaryXXXX--\r\n";
        assertTrue(FileUploadEngine.extractUploadedFiles(body, BOUNDARY).isEmpty());
    }

    @Test
    public void extractUploadedFilesHandlesMissingInput() {
        assertTrue(FileUploadEngine.extractUploadedFiles(null, BOUNDARY).isEmpty());
        assertTrue(FileUploadEngine.extractUploadedFiles("body", null).isEmpty());
        assertTrue(FileUploadEngine.extractUploadedFiles("body", "").isEmpty());
    }

    // ---- isDangerousExtension ----

    @Test
    public void recognisesCommonExecutableAndScriptExtensions() {
        assertTrue(FileUploadEngine.isDangerousExtension("shell.php"));
        assertTrue(FileUploadEngine.isDangerousExtension("shell.PHP"));
        assertTrue(FileUploadEngine.isDangerousExtension("cmd.jsp"));
        assertTrue(FileUploadEngine.isDangerousExtension("payload.exe"));
        assertTrue(FileUploadEngine.isDangerousExtension("script.sh"));
    }

    @Test
    public void ordinaryFileTypesAreNotDangerous() {
        assertFalse(FileUploadEngine.isDangerousExtension("photo.jpg"));
        assertFalse(FileUploadEngine.isDangerousExtension("document.pdf"));
        assertFalse(FileUploadEngine.isDangerousExtension("noextension"));
        assertFalse(FileUploadEngine.isDangerousExtension(null));
    }

    // ---- mimeExtensionMismatch ----

    @Test
    public void flagsDangerousExtensionDeclaredUnderBenignImageMime() {
        assertTrue(FileUploadEngine.mimeExtensionMismatch("shell.php", "image/jpeg"));
        assertTrue(FileUploadEngine.mimeExtensionMismatch("shell.jsp", "image/png; charset=binary"));
    }

    @Test
    public void doesNotFlagOrdinaryExtensionWithMatchingContentType() {
        assertFalse(FileUploadEngine.mimeExtensionMismatch("photo.jpg", "image/jpeg"));
    }

    @Test
    public void doesNotFlagDangerousExtensionWithAnHonestContentType() {
        assertFalse(FileUploadEngine.mimeExtensionMismatch("shell.php", "application/x-php"));
        assertFalse(FileUploadEngine.mimeExtensionMismatch("shell.php", null));
    }

    // ---- findStoredDangerousPath ----

    @Test
    public void findsStoredPathThatKeepsTheDangerousExtension() {
        String responseBody = "{\"url\":\"/uploads/2024/shell.php\",\"status\":\"ok\"}";
        Optional<String> stored = FileUploadEngine.findStoredDangerousPath(responseBody, "shell.php");
        assertEquals(Optional.of("/uploads/2024/shell.php"), stored);
    }

    @Test
    public void noStoredPathWhenExtensionWasStrippedOrRenamed() {
        String responseBody = "{\"url\":\"/uploads/2024/a1b2c3.png\",\"status\":\"ok\"}";
        assertTrue(FileUploadEngine.findStoredDangerousPath(responseBody, "shell.php").isEmpty());
    }

    @Test
    public void findStoredDangerousPathHandlesMissingInput() {
        assertTrue(FileUploadEngine.findStoredDangerousPath(null, "shell.php").isEmpty());
        assertTrue(FileUploadEngine.findStoredDangerousPath("body", null).isEmpty());
    }

    // ---- bypassFilenameVariants ----

    @Test
    public void generatesExpectedBypassShapesFromAnOrdinaryFilename() {
        List<String> variants = FileUploadEngine.bypassFilenameVariants("photo.jpg");
        assertTrue(variants.contains("photo.php"));
        assertTrue(variants.contains("photo.php.jpg"));
        assertTrue(variants.contains("photo.jpg.php"));
        assertTrue(variants.contains("photo.pHp"));
        assertTrue(variants.contains("photo.phtml"));
        assertTrue(variants.contains("photo.php%00.jpg"));
    }

    @Test
    public void bypassFilenameVariantsHandlesAFilenameWithoutAnExtension() {
        List<String> variants = FileUploadEngine.bypassFilenameVariants("noext");
        assertTrue(variants.contains("noext.php"));
        assertTrue(variants.contains("noext.php%00.jpg")); // falls back to a generic safe extension
    }

    @Test
    public void bypassFilenameVariantsIsEmptyForBlankInput() {
        assertTrue(FileUploadEngine.bypassFilenameVariants(null).isEmpty());
        assertTrue(FileUploadEngine.bypassFilenameVariants("").isEmpty());
    }

    // ---- withRenamedFilename ----

    @Test
    public void renamesTheMatchingFilenameAttributeOnly() {
        String body = multipartBody("avatar", "photo.jpg", "image/jpeg");
        String renamed = FileUploadEngine.withRenamedFilename(body, "photo.jpg", "photo.php.jpg");
        assertTrue(renamed.contains("filename=\"photo.php.jpg\""));
        assertFalse(renamed.contains("filename=\"photo.jpg\""));
    }

    @Test
    public void withRenamedFilenameIsNoOpWhenOriginalNotFound() {
        String body = multipartBody("avatar", "photo.jpg", "image/jpeg");
        assertEquals(body, FileUploadEngine.withRenamedFilename(body, "not-present.jpg", "x.php"));
    }

    @Test
    public void withRenamedFilenameHandlesMissingInput() {
        assertNull(FileUploadEngine.withRenamedFilename(null, "a", "b"));
        String body = "unchanged";
        assertEquals(body, FileUploadEngine.withRenamedFilename(body, null, "b"));
        assertEquals(body, FileUploadEngine.withRenamedFilename(body, "a", null));
    }
}
