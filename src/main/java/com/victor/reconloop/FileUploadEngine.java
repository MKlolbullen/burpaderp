package com.victor.reconloop;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * File-upload risk analysis: passively parses observed {@code multipart/form-data} requests for
 * uploaded filenames and their declared content types, flags executable/script extensions and
 * content-type-only bypass attempts, and (for the opt-in active replay test in
 * {@link ActiveTestEngine}) builds a small set of filename-rename bypass payloads and a pure body
 * mutator. Pure and dependency-free so it's directly unit-testable.
 */
final class FileUploadEngine {

    record UploadedFile(String partName, String filename, String declaredContentType) {}

    private static final Pattern BOUNDARY = Pattern.compile("boundary=(?:\"([^\"]+)\"|([^;\\s]+))", Pattern.CASE_INSENSITIVE);
    private static final Pattern DISPOSITION = Pattern.compile(
            "Content-Disposition:\\s*form-data;\\s*name=\"([^\"]*)\"(?:;\\s*filename=\"([^\"]*)\")?",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern PART_CONTENT_TYPE = Pattern.compile("Content-Type:\\s*([^\\r\\n]+)", Pattern.CASE_INSENSITIVE);
    private static final Pattern STORED_PATH = Pattern.compile("[\"']((?:https?://[^\"'\\s]+|/[^\"'\\s]*)\\.[a-zA-Z0-9]{1,6})[\"']");

    /** Extensions many servers execute or interpret directly, regardless of a benign declared MIME type. */
    private static final Set<String> DANGEROUS_EXTENSIONS = Set.of(
            "php", "php2", "php3", "php4", "php5", "php7", "phtml", "phar", "pht",
            "jsp", "jspx", "jsw", "jsv",
            "asp", "aspx", "ashx", "asa", "cer",
            "exe", "dll", "bat", "cmd", "com",
            "sh", "bash", "csh", "ksh",
            "py", "pl", "rb", "cgi",
            "htaccess", "config");

    /** MIME types an attacker commonly declares to slip a dangerous extension past a content-type-only filter. */
    private static final Set<String> BENIGN_LOOKING_CONTENT_TYPES = Set.of(
            "image/jpeg", "image/png", "image/gif", "image/webp", "image/bmp", "image/svg+xml",
            "text/plain", "application/pdf");

    static boolean looksLikeMultipartFileUpload(String contentType) {
        return contentType != null && contentType.toLowerCase(Locale.ROOT).trim().startsWith("multipart/form-data");
    }

    /** Extracts the boundary token from a {@code Content-Type: multipart/form-data; boundary=...} header. */
    static String extractBoundary(String contentType) {
        if (contentType == null) return null;
        Matcher m = BOUNDARY.matcher(contentType);
        if (!m.find()) return null;
        return m.group(1) != null ? m.group(1) : m.group(2);
    }

    /** Parses every part of a multipart body that carries a {@code filename=} attribute. */
    static List<UploadedFile> extractUploadedFiles(String body, String boundary) {
        if (body == null || boundary == null || boundary.isBlank()) return List.of();
        String[] parts = body.split(Pattern.quote("--" + boundary));
        List<UploadedFile> files = new ArrayList<>();
        for (String part : parts) {
            Matcher dm = DISPOSITION.matcher(part);
            if (!dm.find()) continue;
            String filename = dm.group(2);
            if (filename == null || filename.isBlank()) continue;
            String contentType = null;
            Matcher cm = PART_CONTENT_TYPE.matcher(part);
            if (cm.find()) contentType = cm.group(1).trim();
            files.add(new UploadedFile(dm.group(1), filename, contentType));
        }
        return files;
    }

    static boolean isDangerousExtension(String filename) {
        String ext = extension(filename);
        return ext != null && DANGEROUS_EXTENSIONS.contains(ext);
    }

    /**
     * Flags a dangerous (executable/script) extension declared under a benign-looking Content-Type --
     * exactly the shape of a classic content-type-only upload-filter bypass, since many servers execute
     * a file by its extension regardless of what MIME type was declared alongside it.
     */
    static boolean mimeExtensionMismatch(String filename, String declaredContentType) {
        if (!isDangerousExtension(filename) || declaredContentType == null) return false;
        String type = declaredContentType.toLowerCase(Locale.ROOT).split(";")[0].trim();
        return BENIGN_LOOKING_CONTENT_TYPES.contains(type);
    }

    /** Best-effort: does the response reference a stored URL/path that still carries a dangerous extension? */
    static Optional<String> findStoredDangerousPath(String responseBody, String filename) {
        if (responseBody == null || filename == null) return Optional.empty();
        String stem = stem(filename);
        if (stem.isEmpty()) return Optional.empty();
        Matcher m = STORED_PATH.matcher(responseBody);
        while (m.find()) {
            String path = m.group(1);
            if (path.contains(stem) && isDangerousExtension(path)) return Optional.of(path);
        }
        return Optional.empty();
    }

    /**
     * A small, self-authored set of filename-rename bypasses to try against an already-observed
     * upload request: a bare dangerous extension, double-extension tricks in both orders, a
     * case-variant, an alternate PHP-executable extension, and the legacy null-byte truncation bug.
     */
    static List<String> bypassFilenameVariants(String originalFilename) {
        if (originalFilename == null || originalFilename.isBlank()) return List.of();
        String stem = stem(originalFilename);
        if (stem.isBlank()) stem = "rh-upload";
        String ext = extension(originalFilename);
        String safeExt = ext == null ? "jpg" : ext;
        return List.of(
                stem + ".php",
                stem + ".php." + safeExt,
                stem + "." + safeExt + ".php",
                stem + ".pHp",
                stem + ".phtml",
                stem + ".php%00." + safeExt);
    }

    /** Replaces {@code filename="original"} with {@code filename="renamed"} in a multipart body; a no-op if not found. */
    static String withRenamedFilename(String body, String originalFilename, String newFilename) {
        if (body == null || originalFilename == null || newFilename == null) return body;
        String target = "filename=\"" + originalFilename + "\"";
        String replacement = "filename=\"" + newFilename + "\"";
        int at = body.indexOf(target);
        if (at < 0) return body;
        return body.substring(0, at) + replacement + body.substring(at + target.length());
    }

    private static String extension(String filename) {
        if (filename == null) return null;
        int dot = filename.lastIndexOf('.');
        if (dot < 0 || dot == filename.length() - 1) return null;
        return filename.substring(dot + 1).toLowerCase(Locale.ROOT);
    }

    private static String stem(String filename) {
        if (filename == null) return "";
        int slash = Math.max(filename.lastIndexOf('/'), filename.lastIndexOf('\\'));
        String base = filename.substring(slash + 1);
        int dot = base.lastIndexOf('.');
        return dot > 0 ? base.substring(0, dot) : base;
    }

    private FileUploadEngine() {}
}
