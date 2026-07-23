package com.victor.reconloop;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Standalone, Burp-free command-line scanner for CI. Fetches target URLs over HTTP and runs Recon
 * Hound's pure passive engines — secret detection (RegexHound), software-composition analysis
 * (DependencyVulnEngine), heuristic DOM-XSS (DomXssEngine) and exposed-source-map detection — then
 * writes a SARIF 2.1.0 report and exits non-zero when findings meet a severity threshold, so it can
 * gate a pipeline. Uses only dependency-free, Montoya-free classes, so it runs with plain
 * {@code java -jar burp-recon-hound.jar <urls>}.
 */
public final class ReconHoundCli {

    private record Finding(String ruleId, String name, String severity, String url, String detail) {}

    public static void main(String[] args) throws Exception {
        List<String> urls = new ArrayList<>();
        String output = "recon-hound.sarif";
        String failOn = "high";

        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            switch (arg) {
                case "-o", "--output" -> output = args[++i];
                case "--fail-on" -> failOn = args[++i].toLowerCase(Locale.ROOT);
                case "-f", "--file" -> {
                    for (String line : Files.readAllLines(Path.of(args[++i]))) {
                        String value = line.trim();
                        if (value.startsWith("http")) urls.add(value);
                    }
                }
                case "-h", "--help" -> { printHelp(); return; }
                default -> { if (arg.startsWith("http")) urls.add(arg); }
            }
        }

        if (urls.isEmpty()) {
            System.err.println("No target URLs supplied.");
            printHelp();
            System.exit(2);
        }

        HttpClient http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(15))
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();
        RegexHound regex = new RegexHound();
        DependencyVulnEngine sca = new DependencyVulnEngine();
        List<Finding> findings = new ArrayList<>();

        for (String url : urls) {
            try {
                HttpResponse<String> response = http.send(
                        HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(30)).GET().build(),
                        HttpResponse.BodyHandlers.ofString());
                String body = response.body();
                String contentType = response.headers().firstValue("content-type").orElse("");
                System.err.println("[recon-hound] " + response.statusCode() + " " + url + " (" + body.length() + " bytes)");

                for (RegexHound.Finding f : regex.scan(body, "response", url, false)) {
                    if (f.rule().severity() == RegexHound.Severity.INFO) continue;
                    findings.add(new Finding("secret-" + slug(f.rule().name()), "Secret: " + f.rule().name(),
                            severity(f.rule().severity()), url,
                            "Provider " + f.rule().provider() + "; value " + RegexHound.redact(f.value())));
                }
                for (DependencyVulnEngine.LibIssue lib : sca.scan(url, body)) {
                    findings.add(new Finding("sca-" + slug(lib.library()),
                            "Vulnerable dependency: " + lib.library() + " " + lib.version(),
                            lib.severity(), url, lib.detail() + " (" + lib.reference() + ")"));
                }
                boolean scriptish = contentType.contains("javascript") || contentType.contains("html")
                        || stripQuery(url).endsWith(".js");
                if (scriptish) {
                    for (DomXssEngine.DomFinding d : DomXssEngine.analyze(body)) {
                        findings.add(new Finding("domxss-" + slug(d.sink()),
                                "Potential DOM XSS (" + d.source() + " -> " + d.sink() + ")", "MEDIUM", url, d.snippet()));
                    }
                }
                if (SourceMapMiner.looksLikeSourceMap(url, contentType, body)) {
                    findings.add(new Finding("sourcemap", "Source map exposed", "LOW", url,
                            "A JavaScript source map is publicly accessible."));
                }
            } catch (Exception e) {
                System.err.println("[recon-hound] error fetching " + url + ": " + e.getMessage());
            }
        }

        Files.writeString(Path.of(output), toSarif(findings));
        System.err.println("[recon-hound] " + findings.size() + " finding(s) written to " + output);

        int threshold = rank(failOn);
        long breaching = threshold < 0 ? 0
                : findings.stream().filter(f -> rank(f.severity().toLowerCase(Locale.ROOT)) <= threshold).count();
        if (breaching > 0) {
            System.err.println("[recon-hound] " + breaching + " finding(s) at or above '" + failOn + "' — failing the build.");
            System.exit(1);
        }
    }

    private static String toSarif(List<Finding> findings) {
        java.util.LinkedHashMap<String, Finding> rules = new java.util.LinkedHashMap<>();
        for (Finding f : findings) rules.putIfAbsent(f.ruleId(), f);

        StringBuilder rulesJson = new StringBuilder();
        boolean first = true;
        for (var entry : rules.entrySet()) {
            if (!first) rulesJson.append(",");
            first = false;
            rulesJson.append("{\"id\":\"").append(esc(entry.getKey())).append("\",\"name\":\"")
                    .append(esc(entry.getValue().name())).append("\",\"shortDescription\":{\"text\":\"")
                    .append(esc(entry.getValue().name())).append("\"}}");
        }

        StringBuilder resultsJson = new StringBuilder();
        first = true;
        for (Finding f : findings) {
            if (!first) resultsJson.append(",");
            first = false;
            resultsJson.append("{\"ruleId\":\"").append(esc(f.ruleId())).append("\",\"level\":\"")
                    .append(level(f.severity())).append("\",\"message\":{\"text\":\"")
                    .append(esc(f.name() + " — " + f.detail())).append("\"},\"locations\":[{\"physicalLocation\":"
                    + "{\"artifactLocation\":{\"uri\":\"").append(esc(f.url())).append("\"}}}]}");
        }

        return "{\"$schema\":\"https://json.schemastore.org/sarif-2.1.0.json\",\"version\":\"2.1.0\","
                + "\"runs\":[{\"tool\":{\"driver\":{\"name\":\"Recon Hound CLI\",\"informationUri\":"
                + "\"https://github.com/MKlolbullen/burpaderp\",\"rules\":[" + rulesJson + "]}},"
                + "\"results\":[" + resultsJson + "]}]}";
    }

    private static String severity(RegexHound.Severity s) {
        return switch (s) {
            case CRITICAL, HIGH -> "HIGH";
            case MEDIUM -> "MEDIUM";
            case LOW -> "LOW";
            case INFO -> "INFO";
        };
    }

    private static String level(String severity) {
        return switch (severity.toUpperCase(Locale.ROOT)) {
            case "HIGH", "CRITICAL" -> "error";
            case "MEDIUM" -> "warning";
            default -> "note";
        };
    }

    private static int rank(String severity) {
        return switch (severity) {
            case "high", "critical" -> 0;
            case "medium" -> 1;
            case "low" -> 2;
            case "info" -> 3;
            default -> -1;   // "none" (or unknown) never fails the build
        };
    }

    private static String slug(String value) {
        return value == null ? "issue"
                : value.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]+", "-").replaceAll("(^-|-$)", "");
    }

    private static String stripQuery(String url) {
        int q = url.indexOf('?');
        return (q >= 0 ? url.substring(0, q) : url).toLowerCase(Locale.ROOT);
    }

    private static String esc(String value) {
        return LlmProvider.jsonEscape(value == null ? "" : value);
    }

    private static void printHelp() {
        System.err.println("""
                Recon Hound CLI — Burp-free CI scanner (secrets, SCA, DOM-XSS, exposed source maps)

                Usage:
                  java -jar burp-recon-hound.jar [options] <url> [<url> ...]

                Options:
                  -f, --file <path>     Read target URLs (one per line) from a file
                  -o, --output <path>   SARIF output path (default: recon-hound.sarif)
                      --fail-on <lvl>   Exit non-zero if any finding is >= lvl:
                                        high (default) | medium | low | none
                  -h, --help            Show this help

                Exit codes: 0 clean, 1 findings at/above --fail-on, 2 bad usage.""");
    }
}
