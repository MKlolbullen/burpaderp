package com.victor.reconloop;

import java.io.PrintStream;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/** Burp-free offline response analysis. Live fetching stays disabled until it shares the outbound gate. */
public final class ReconHoundCli {

    private record Finding(String ruleId, String name, String severity, String url, String detail) {}
    record Options(List<String> urls, Path output, String failOn, boolean help, Path bodyFile, String contentType) {}

    public static void main(String[] args) throws Exception {
        int status = run(args, System.err);
        if (status != 0) System.exit(status);
    }

    static int run(String[] args, PrintStream err) throws Exception {
        Options options;
        try {
            options = parseOptions(args);
        } catch (IllegalArgumentException | java.io.IOException e) {
            err.println("Error: " + e.getMessage());
            printHelp(err);
            return 2;
        }
        if (options.help()) {
            printHelp(err);
            return 0;
        }
        if (options.urls().isEmpty()) {
            err.println("No target URL supplied as artifact metadata.");
            printHelp(err);
            return 2;
        }
        if (options.bodyFile() == null) {
            err.println(ExternalTargetEgress.blocked("CLI live fetching")
                    + " Use --body-file to analyze a saved response; no report was written.");
            return 3;
        }
        if (!Files.isRegularFile(options.bodyFile())) {
            err.println("--body-file must name a regular local file.");
            return 2;
        }
        String body;
        try {
            body = Files.readString(options.bodyFile());
        } catch (java.io.IOException e) {
            err.println("Could not read --body-file: " + e.getMessage());
            return 2;
        }
        String url = options.urls().getFirst(); // Metadata only: never resolved or fetched.
        String contentType = options.contentType();
        RegexHound regex = new RegexHound();
        DependencyVulnEngine sca = new DependencyVulnEngine();
        List<Finding> findings = new ArrayList<>();

        for (RegexHound.Finding f : regex.scan(body, "response", url, false)) {
            if (f.rule().severity() == RegexHound.Severity.INFO) continue;
            findings.add(new Finding("secret-" + slug(f.rule().name()), "Secret: " + f.rule().name(),
                    severity(f.rule().severity()), url,
                    "Provider " + f.rule().provider() + "; value " + RegexHound.redact(f.value())));
        }
        for (var match : new GfPatternLoader().scan(body)) {
            if (match.severity().equals("INFO")) continue;
            findings.add(new Finding("gf-" + match.ruleId(), "GF " + match.category() + " candidate: " + match.ruleId(),
                    match.severity(), match.displaySourceUrl(url), "Passive SIGNAL; validity/impact unverified. Provider " + match.provider()
                    + "; value " + match.displayValue()));
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
            findings.add(new Finding("sourcemap", "Source map detected in saved response", "LOW", url,
                    "The saved response contains a JavaScript source map; public accessibility was not checked."));
        }
        Path parent = options.output().toAbsolutePath().getParent();
        if (parent != null) Files.createDirectories(parent);
        Files.writeString(options.output(), toSarif(findings));
        err.println("[recon-hound] " + findings.size() + " finding(s) written to " + options.output());

        int threshold = rank(options.failOn());
        long breaching = threshold < 0 ? 0
                : findings.stream().filter(f -> rank(f.severity().toLowerCase(Locale.ROOT)) <= threshold).count();
        if (breaching > 0) {
            err.println("[recon-hound] " + breaching + " finding(s) at or above '" + options.failOn() + "' — failing the build.");
            return 1;
        }
        return 0;
    }

    static Options parseOptions(String[] args) throws Exception {
        Set<String> urls = new LinkedHashSet<>();
        Path output = Path.of("recon-hound.sarif");
        String failOn = "high";
        boolean help = false;
        Path bodyFile = null;
        String contentType = "text/html";

        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            switch (arg) {
                case "-o", "--output" -> output = Path.of(requireValue(args, ++i, arg));
                case "--fail-on" -> failOn = requireValue(args, ++i, arg).toLowerCase(Locale.ROOT);
                case "-f", "--file" -> {
                    Path input = Path.of(requireValue(args, ++i, arg));
                    for (String line : Files.readAllLines(input)) {
                        String value = line.strip();
                        if (!value.isEmpty() && !value.startsWith("#")) urls.add(validateUrl(value));
                    }
                }
                case "--body-file" -> bodyFile = Path.of(requireValue(args, ++i, arg));
                case "--content-type" -> contentType = requireValue(args, ++i, arg).toLowerCase(Locale.ROOT);
                case "-h", "--help" -> help = true;
                default -> {
                    if (arg.startsWith("-")) throw new IllegalArgumentException("unknown option: " + arg);
                    urls.add(validateUrl(arg));
                }
            }
        }
        if (rank(failOn) < 0 && !"none".equals(failOn)) {
            throw new IllegalArgumentException("invalid --fail-on level: " + failOn);
        }
        if (bodyFile != null && urls.size() != 1) {
            throw new IllegalArgumentException("--body-file requires exactly one HTTP(S) URL as artifact metadata");
        }
        return new Options(List.copyOf(urls), output, failOn, help, bodyFile, contentType);
    }

    private static String requireValue(String[] args, int index, String option) {
        if (index >= args.length || args[index].isBlank()) {
            throw new IllegalArgumentException("missing value for " + option);
        }
        return args[index];
    }

    private static String validateUrl(String value) {
        try {
            URI uri = URI.create(value);
            String scheme = uri.getScheme();
            if (uri.getHost() == null || !("http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme))) {
                throw new IllegalArgumentException("target must be an absolute HTTP(S) URL: " + value);
            }
            return uri.toString();
        } catch (IllegalArgumentException e) {
            if (e.getMessage() != null && e.getMessage().startsWith("target must")) throw e;
            throw new IllegalArgumentException("invalid target URL: " + value, e);
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

    private static void printHelp(PrintStream err) {
        err.println("""
                Recon Hound CLI — Burp-free offline CI scanner (secrets, SCA, DOM-XSS, exposed source maps)

                Usage:
                  java -jar burp-recon-hound.jar [options] --body-file <path> <artifact-url>

                Options:
                      --body-file <p>  Analyze a saved response body; URL is metadata only
                      --content-type <t> Content type for offline analysis (default: text/html)
                  -f, --file <path>     Read target URLs (one per line) from a file
                  -o, --output <path>   SARIF output path (default: recon-hound.sarif)
                      --fail-on <lvl>   Exit non-zero if any finding is >= lvl:
                                        high (default) | medium | low | info | none
                  -h, --help            Show this help

                Live HTTP fetching is disabled pending the outbound gateway (#44).
                Exit codes: 0 clean, 1 findings at/above --fail-on, 2 bad input, 3 live fetching blocked.""");
    }
}
