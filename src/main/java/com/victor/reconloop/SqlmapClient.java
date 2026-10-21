package com.victor.reconloop;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Offline sqlmap argument/output helpers. Process execution is fail-closed until egress is governed. */
final class SqlmapClient {

    record Target(String url, String method, String parameter, String body, String cookieHeader) {}

    record RunResult(boolean started, boolean vulnerable, List<String> injectionTypes, String rawOutput, String error) {}

    private static final Pattern TYPE_LINE = Pattern.compile("Type:\\s*(.+)");

    SqlmapClient(String sqlmapPath) {
        // Retained for callers/settings compatibility; no binary is executed, including --version.
    }

    boolean isAvailable() { return false; }

    RunResult run(Target target, int level, int risk, String techniques, String extraArgs, long timeoutSeconds) {
        return new RunResult(false, false, List.of(), "", ExternalTargetEgress.blocked("sqlmap"));
    }

    // ---- pure cores (unit-tested) ----

    /**
     * Builds sqlmap's argument list for {@code target}. Always non-interactive ({@code --batch}); the
     * default level/risk/technique flags are conservative confirmation settings, never dumping or
     * shell-spawning options -- those only appear via a caller-supplied {@code extraArgs}.
     */
    static List<String> buildArgs(Target target, int level, int risk, String techniques, String extraArgs) {
        List<String> args = new ArrayList<>();
        args.add("--batch");
        args.add("-u");
        args.add(target.url());
        if ("POST".equalsIgnoreCase(target.method()) && target.body() != null && !target.body().isBlank()) {
            args.add("--data=" + target.body());
        }
        if (target.parameter() != null && !target.parameter().isBlank()) {
            args.add("-p");
            args.add(target.parameter());
        }
        if (target.cookieHeader() != null && !target.cookieHeader().isBlank()) {
            args.add("--cookie=" + target.cookieHeader());
        }
        args.add("--level=" + clamp(level, 1, 5));
        args.add("--risk=" + clamp(risk, 1, 3));
        if (techniques != null && !techniques.isBlank()) {
            args.add("--technique=" + techniques.trim());
        }
        if (extraArgs != null && !extraArgs.isBlank()) {
            for (String token : extraArgs.trim().split("\\s+")) {
                if (!token.isBlank()) args.add(token);
            }
        }
        return args;
    }

    static int clamp(int value, int min, int max) {
        return Math.max(min, Math.min(max, value));
    }

    /** True if sqlmap's output reports at least one confirmed injection point. */
    static boolean looksVulnerable(String output) {
        return output != null && output.contains("Parameter:") && output.contains("Type:");
    }

    /** Every distinct injection technique ("boolean-based blind", "time-based blind", ...) sqlmap reported. */
    static List<String> extractInjectionTypes(String output) {
        if (output == null) return List.of();
        List<String> types = new ArrayList<>();
        Matcher matcher = TYPE_LINE.matcher(output);
        while (matcher.find()) {
            String type = matcher.group(1).trim();
            if (!types.contains(type)) types.add(type);
        }
        return types;
    }

    /** True if sqlmap explicitly reported no injectable parameter (a confident negative, not just an error). */
    static boolean looksNotInjectable(String output) {
        if (output == null) return false;
        String lower = output.toLowerCase(Locale.ROOT);
        return lower.contains("does not seem to be injectable") || lower.contains("do not appear to be injectable");
    }
}
