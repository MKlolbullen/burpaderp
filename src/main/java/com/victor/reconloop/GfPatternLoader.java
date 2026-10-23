package com.victor.reconloop;

import java.io.IOException;
import java.io.InputStream;
import java.net.IDN;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.regex.*;

/** Passive, bounded local text matching. Pack engines/commands are never executed. */
final class GfPatternLoader {
    static final int MAX_INPUT_CHARS = 1 << 20, MAX_PACK_BYTES = 512 << 10;
    static final int MAX_MATCHES = 2000, MAX_RULE_MATCHES = 128, MAX_RULES = 1024, MAX_PACKS = 128;
    record GfMatch(String pack, String ruleId, String provider, String category, String severity,
                   String value, int start, int end) {
        boolean sensitive() { return !Set.of("network", "identifier", "hint", "endpoint").contains(category); }
        String displayValue() { return sensitive() ? RegexHound.redact(value) : value; }
        String displaySourceUrl(String url) {
            try {
                URI source = URI.create(url);
                String path = source.getPath();
                if (path != null && sensitive()) path = path.replace(value, "[redacted]");
                return new URI(source.getScheme(), null, source.getHost(), source.getPort(), path, null, null).toString();
            } catch (IllegalArgumentException | URISyntaxException invalid) { return ""; }
        }
    }
    private record Rule(String id, String provider, String category, String severity, Pattern pattern,
                        int capture, double entropy, String validator, List<String> keywords) {}
    private record Pack(String name, List<Rule> rules) {}
    private final List<Pack> packs;
    private final List<String> diagnostics;

    GfPatternLoader() { this(defaultDirectories(), true); }
    GfPatternLoader(List<Path> directories) { this(directories, false); }
    GfPatternLoader(List<Path> directories, boolean bundled) {
        var warnings = new ArrayList<String>();
        var loaded = new TreeMap<String, Pack>();
        if (bundled) {
            try (InputStream index = GfPatternLoader.class.getResourceAsStream("/gf-packs/index.txt")) {
                if (index == null) warnings.add("bundled packs: index missing");
                if (index != null) for (String name : new String(index.readNBytes(8192), StandardCharsets.UTF_8).split("\\R")) {
                    if (!name.matches("rh-[a-z0-9-]+\\.json")) continue;
                    try (InputStream stream = GfPatternLoader.class.getResourceAsStream("/gf-packs/" + name)) {
                        if (stream == null) warnings.add(name + ": missing bundled resource");
                        else put(loaded, parse(name, stream.readNBytes(MAX_PACK_BYTES + 1), warnings));
                    }
                }
            } catch (IOException e) { warnings.add("bundled packs: read failed"); }
        }
        // Earlier directories have precedence; same-name packs replace, rather than duplicate.
        for (Path dir : directories.reversed()) {
            if (!Files.isDirectory(dir)) continue;
            try (var paths = Files.list(dir)) {
                for (Path file : paths.filter(p -> p.getFileName().toString().endsWith(".json")).sorted().limit(MAX_PACKS).toList()) {
                    String name = file.getFileName().toString();
                    if (!name.matches("[A-Za-z0-9_.-]{1,100}\\.json")) continue;
                    if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) { warnings.add(name + ": not a regular file"); continue; }
                    try (InputStream stream = Files.newInputStream(file)) {
                        put(loaded, parse(name, stream.readNBytes(MAX_PACK_BYTES + 1), warnings));
                    } catch (IOException e) { warnings.add(name + ": read failed"); }
                }
            } catch (IOException e) { warnings.add("pack directory: read failed"); }
        }
        var bounded = new ArrayList<Pack>(); int count = 0;
        for (Pack pack : loaded.values()) {
            if (bounded.size() >= MAX_PACKS || count + pack.rules.size() > MAX_RULES) {
                warnings.add(pack.name + ": catalog limit reached"); continue;
            }
            count += pack.rules.size(); bounded.add(pack);
        }
        packs = List.copyOf(bounded); diagnostics = List.copyOf(warnings);
    }
    int packCount() { return packs.size(); }
    int ruleCount() { return packs.stream().mapToInt(p -> p.rules.size()).sum(); }
    List<String> diagnostics() { return diagnostics; }

    List<GfMatch> scan(String input) {
        if (input == null || input.isEmpty()) return List.of();
        String text = input.substring(0, Math.min(input.length(), MAX_INPUT_CHARS));
        String lower = text.toLowerCase(Locale.ROOT);
        var out = new ArrayList<GfMatch>(); var seen = new HashSet<String>();
        for (Pack pack : packs) for (Rule rule : pack.rules) {
            if (!rule.keywords.isEmpty() && rule.keywords.stream().noneMatch(lower::contains)) continue;
            Matcher matcher = rule.pattern.matcher(text); int cursor = 0, attempts = 0;
            try {
                while (cursor <= text.length() && attempts++ < MAX_RULE_MATCHES && matcher.find(cursor)) {
                    String value = matcher.group(rule.capture);
                    int start = matcher.start(rule.capture), end = matcher.end(rule.capture);
                    cursor = Math.max(cursor + 1, end < 0 ? matcher.end() : end);
                    if (value == null || value.isBlank() || !valid(rule.validator, value)) continue;
                    if (rule.validator.equals("ipv4") && rule.category.equals("network")
                            && embeddedIpv4Suffix(text, start, end)) continue;
                    if (rule.entropy > 0 && (RegexHound.isPlaceholder(value)
                            || RegexHound.shannonEntropy(value) < rule.entropy)) continue;
                    if (!seen.add(pack.name + "\0" + rule.id + "\0" + value)) continue;
                    out.add(new GfMatch(pack.name, rule.id, rule.provider, rule.category, rule.severity, value, start, end));
                    if (out.size() >= MAX_MATCHES) return List.copyOf(out);
                }
            } catch (StackOverflowError invalidLocalPattern) {
                // User-authored Java regexes are trusted configuration, not a time-bounded engine.
                // Do not let a recursive local expression tear down the passive scanner thread.
            }
        }
        return List.copyOf(out);
    }

    /** Keep a mapped/mixed IPv6 literal as one inventory value, without hiding standalone IPv4. */
    private static boolean embeddedIpv4Suffix(String text, int start, int end) {
        if (start == 0 || text.charAt(start - 1) != ':') return false;
        int left = start - 1;
        while (left > 0 && end - left < 64 && ipv6Character(text.charAt(left - 1))) left--;
        // Do not accept a truncated enclosure or an IPv4 value followed by another address group.
        if ((left > 0 && ipv6Character(text.charAt(left - 1)))
                || (end < text.length() && ipv6Character(text.charAt(end)))) return false;
        return RegexHound.validIpv6(text.substring(left, end));
    }
    private static boolean ipv6Character(char c) {
        return c == ':' || c == '.' || c >= '0' && c <= '9'
                || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F';
    }

    private static List<Path> defaultDirectories() {
        var dirs = new ArrayList<Path>();
        String override = System.getenv("GF_PATTERNS_DIR");
        if (override != null && !override.isBlank()) dirs.add(Path.of(override));
        Path home = Path.of(System.getProperty("user.home"));
        dirs.add(home.resolve(".config/gf")); dirs.add(home.resolve(".gf"));
        return dirs;
    }
    private static void put(Map<String, Pack> loaded, Pack pack) { if (pack != null) loaded.put(pack.name, pack); }
    private static Pack parse(String filename, byte[] bytes, List<String> diagnostics) {
        if (bytes.length > MAX_PACK_BYTES) { diagnostics.add(filename + ": file too large"); return null; }
        try {
            Map<String, Object> object = Json.asObject(Json.parseStrict(new String(bytes, StandardCharsets.UTF_8)));
            if (object == null) throw new IllegalArgumentException();
            String flags = optionalText(object, "flags", "");
            boolean ci = false, literal = false;
            for (String flag : flags.strip().split("\\s+")) {
                if (flag.isEmpty()) continue;
                if (flag.equals("--ignore-case")) { ci = true; continue; }
                if (flag.equals("--fixed-strings")) { literal = true; continue; }
                if (!flag.matches("-[EHhIniorslaPcF]+")) throw new IllegalArgumentException();
                ci |= flag.indexOf('i') >= 0; literal |= flag.indexOf('F') >= 0;
            }
            List<String> patterns = new ArrayList<>();
            // gf gives the single pattern precedence over the array.
            if (object.get("pattern") instanceof String single && !single.isEmpty()) patterns.add(single);
            else if (object.get("patterns") instanceof List<?> array) {
                for (Object entry : array) {
                    if (!(entry instanceof String raw)) throw new IllegalArgumentException();
                    patterns.add(raw);
                }
            }
            if (patterns.isEmpty() || patterns.size() > 256) throw new IllegalArgumentException();
            Map<String, Object> extension = object.containsKey("reconhound") ? Json.asObject(object.get("reconhound")) : null;
            List<?> metadata = null;
            if (object.containsKey("reconhound")) {
                if (extension == null || !(extension.get("schemaVersion") instanceof Number n) || n.doubleValue() != 1
                        || !(extension.get("rules") instanceof List<?> list) || list.size() != patterns.size()) throw new IllegalArgumentException();
                metadata = list;
            }
            var rules = new ArrayList<Rule>(); var ids = new HashSet<String>();
            for (int i = 0; i < patterns.size(); i++) {
                try {
                    String raw = patterns.get(i);
                    if (raw.isEmpty() || raw.length() > 4096) throw new IllegalArgumentException();
                    Map<String, Object> data = metadata == null ? Map.of() : Json.asObject(metadata.get(i));
                    if (data == null || (metadata != null && !raw.equals(data.get("pattern")))) throw new IllegalArgumentException();
                    String id = optionalText(data, "id", "pattern-" + i);
                    String provider = optionalText(data, "provider", "gf");
                    String category = optionalText(data, "category", "unclassified");
                    String severity = optionalText(data, "severity", "INFO");
                    String validator = optionalText(data, "validator", "none");
                    if (!id.matches("[a-zA-Z0-9_.-]{1,100}") || !provider.matches("[a-zA-Z0-9_.-]{1,80}")
                            || !Set.of("unclassified", "secret", "private-key", "credential", "token", "identifier", "network", "endpoint", "hint").contains(category)
                            || !Set.of("HIGH", "MEDIUM", "LOW", "INFO").contains(severity)
                            || !Set.of("none", "ipv4", "ipv6", "cidr", "hostname", "jwt").contains(validator)) throw new IllegalArgumentException();
                    int capture = integer(data, "capture", 0, 0, 32);
                    double entropy = data.getOrDefault("minEntropy", 0) instanceof Number n ? n.doubleValue() : -1;
                    if (!Double.isFinite(entropy) || entropy < 0 || entropy > 8) throw new IllegalArgumentException();
                    Pattern compiled = Pattern.compile(literal ? Pattern.quote(raw) : raw,
                            Pattern.MULTILINE | (ci ? Pattern.CASE_INSENSITIVE : 0));
                    if (capture > compiled.matcher("").groupCount() || !ids.add(id)) throw new IllegalArgumentException();
                    var keywords = new ArrayList<String>();
                    if (data.containsKey("keywords")) {
                        if (!(data.get("keywords") instanceof List<?> words) || words.size() > 64) throw new IllegalArgumentException();
                        for (Object word : words) {
                            if (!(word instanceof String s) || s.isBlank() || s.length() > 100) throw new IllegalArgumentException();
                            keywords.add(s.toLowerCase(Locale.ROOT));
                        }
                    }
                    rules.add(new Rule(id, provider, category, severity, compiled, capture, entropy, validator, List.copyOf(keywords)));
                } catch (IllegalArgumentException e) { diagnostics.add(filename + ": invalid rule " + i); }
            }
            return rules.isEmpty() ? null : new Pack(filename.substring(0, filename.length() - 5), List.copyOf(rules));
        } catch (IllegalArgumentException e) { diagnostics.add(filename + ": invalid JSON or pack options"); return null; }
    }
    private static String optionalText(Map<String, Object> data, String key, String fallback) {
        Object value = data.getOrDefault(key, fallback);
        if (!(value instanceof String text)) throw new IllegalArgumentException();
        return text;
    }
    private static int integer(Map<String, Object> data, String key, int fallback, int min, int max) {
        if (!(data.getOrDefault(key, fallback) instanceof Number n) || n.doubleValue() != n.intValue()
                || n.intValue() < min || n.intValue() > max) throw new IllegalArgumentException();
        return n.intValue();
    }
    private static boolean valid(String validator, String value) {
        return switch (validator) {
            case "ipv4" -> RegexHound.validIpv4(value);
            case "ipv6" -> RegexHound.validIpv6(value.split("%", 2)[0]);
            case "cidr" -> {
                String[] parts = value.split("/", -1);
                try { yield parts.length == 2 && RegexHound.validIpv4(parts[0]) && Integer.parseInt(parts[1]) >= 0 && Integer.parseInt(parts[1]) <= 32; }
                catch (NumberFormatException invalid) { yield false; }
            }
            case "hostname" -> value.length() <= 253 && !value.matches("[0-9.]+") && Arrays.stream(value.split("\\.")).allMatch(s ->
                    !s.isEmpty() && s.length() <= 63 && !s.startsWith("-") && !s.endsWith("-")) && validIdn(value);
            case "jwt" -> {
                try {
                    String[] parts = value.split("\\.", -1);
                    var header = Json.asObject(Json.parseStrict(new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8)));
                    var payload = Json.asObject(Json.parseStrict(new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8)));
                    yield parts.length == 3 && header != null && payload != null && header.get("alg") instanceof String alg && !alg.isBlank()
                            && (!parts[2].isEmpty() || alg.equals("none"));
                } catch (IllegalArgumentException | IndexOutOfBoundsException malformed) { yield false; }
            }
            default -> true;
        };
    }
    private static boolean validIdn(String value) {
        try { IDN.toASCII(value, IDN.USE_STD3_ASCII_RULES); return true; }
        catch (IllegalArgumentException invalid) { return false; }
    }
}
