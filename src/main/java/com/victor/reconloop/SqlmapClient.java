package com.victor.reconloop;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Opt-in integration with a real, locally-installed sqlmap binary for deeper confirmation of a
 * parameter already flagged by {@link ActiveTestEngine}'s native SQLi test. Recon Hound's own test is
 * a lightweight, best-effort confirmation; sqlmap is the mature, real tool for thorough confirmation
 * and (only if the user explicitly supplies the flags for it) further exploitation against a target
 * they are authorized to test.
 *
 * <p>Command-line construction and output parsing are pure functions, directly unit-testable; actually
 * spawning the process is a thin {@link ProcessBuilder} wrapper. The default flags built by
 * {@link #buildArgs} never include destructive/exploitation options (dumping, OS/SQL shells, file
 * read/write) -- those only appear if the caller explicitly types them into {@code extraArgs}.
 */
final class SqlmapClient {

    record Target(String url, String method, String parameter, String body, String cookieHeader) {}

    record RunResult(boolean started, boolean vulnerable, List<String> injectionTypes, String rawOutput, String error) {}

    private static final Pattern TYPE_LINE = Pattern.compile("Type:\\s*(.+)");

    private final String sqlmapPath;

    SqlmapClient(String sqlmapPath) {
        this.sqlmapPath = (sqlmapPath == null || sqlmapPath.isBlank()) ? "sqlmap" : sqlmapPath.trim();
    }

    /** True if the configured sqlmap binary can actually be started (`sqlmap --version` succeeds). */
    boolean isAvailable() {
        try {
            Process process = new ProcessBuilder(sqlmapPath, "--version").redirectErrorStream(true).start();
            boolean finished = process.waitFor(10, TimeUnit.SECONDS);
            if (!finished) { process.destroyForcibly(); return false; }
            return process.exitValue() == 0;
        } catch (IOException e) {
            return false;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    /** Runs sqlmap against {@code target} and blocks (from the caller's worker thread) until it exits or times out. */
    RunResult run(Target target, int level, int risk, String techniques, String extraArgs, long timeoutSeconds) {
        List<String> command = new ArrayList<>();
        command.add(sqlmapPath);
        command.addAll(buildArgs(target, level, risk, techniques, extraArgs));

        ExecutorService outputReader = Executors.newSingleThreadExecutor(r -> {
            Thread thread = new Thread(r, "Recon-Hound-sqlmap-output");
            thread.setDaemon(true);
            return thread;
        });
        Process process = null;
        Future<String> outputFuture = null;
        try {
            process = new ProcessBuilder(command).redirectErrorStream(true).start();
            Process runningProcess = process;
            outputFuture = outputReader.submit(() ->
                    new String(runningProcess.getInputStream().readAllBytes(), StandardCharsets.UTF_8));

            boolean finished = process.waitFor(Math.max(1, timeoutSeconds), TimeUnit.SECONDS);
            if (!finished) {
                process.destroy();
                if (!process.waitFor(2, TimeUnit.SECONDS)) process.destroyForcibly();
                String partial = readOutput(outputFuture, 2);
                return new RunResult(true, false, List.of(), partial,
                        "sqlmap timed out after " + timeoutSeconds + "s (partial output captured)");
            }

            String output = readOutput(outputFuture, 2);
            return new RunResult(true, looksVulnerable(output), extractInjectionTypes(output), output, null);
        } catch (IOException e) {
            return new RunResult(false, false, List.of(), "",
                    "sqlmap not found or failed to start (" + sqlmapPath + "): " + e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            if (process != null) process.destroyForcibly();
            return new RunResult(false, false, List.of(), "", "interrupted while waiting for sqlmap");
        } finally {
            if (outputFuture != null && !outputFuture.isDone()) outputFuture.cancel(true);
            outputReader.shutdownNow();
        }
    }

    private static String readOutput(Future<String> outputFuture, long timeoutSeconds) {
        if (outputFuture == null) return "";
        try {
            return outputFuture.get(timeoutSeconds, TimeUnit.SECONDS);
        } catch (Exception e) {
            outputFuture.cancel(true);
            return "";
        }
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
