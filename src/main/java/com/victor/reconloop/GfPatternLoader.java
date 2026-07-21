package com.victor.reconloop;

import java.io.IOException;
import java.nio.file.*;
import java.util.*;
import java.util.regex.*;

final class GfPatternLoader {
    record GfMatch(String pack, String pattern, String value, int start, int end) {}
    private record Pack(String name, List<Pattern> patterns) {}

    private final List<Pack> packs;

    GfPatternLoader() {
        this(defaultDirectories());
    }

    GfPatternLoader(List<Path> directories) {
        this.packs = load(directories);
    }

    int packCount() { return packs.size(); }

    List<GfMatch> scan(String text) {
        if (text == null || text.isBlank()) return List.of();
        ArrayList<GfMatch> out = new ArrayList<>();
        for (Pack pack : packs) {
            for (Pattern pattern : pack.patterns()) {
                Matcher m = pattern.matcher(text);
                int guard = 0;
                while (m.find() && guard++ < 1000) {
                    out.add(new GfMatch(pack.name(), pattern.pattern(), m.group(), m.start(), m.end()));
                }
            }
        }
        return out;
    }

    private static List<Path> defaultDirectories() {
        String override = System.getenv("GF_PATTERNS_DIR");
        ArrayList<Path> dirs = new ArrayList<>();
        if (override != null && !override.isBlank()) dirs.add(Path.of(override));
        dirs.add(Path.of(System.getProperty("user.home"), ".gf"));
        return dirs;
    }

    private static List<Pack> load(List<Path> dirs) {
        ArrayList<Pack> out = new ArrayList<>();
        for (Path dir : dirs) {
            if (!Files.isDirectory(dir)) continue;
            try (DirectoryStream<Path> stream = Files.newDirectoryStream(dir, "*.json")) {
                for (Path file : stream) {
                    Pack pack = parse(file);
                    if (pack != null && !pack.patterns().isEmpty()) out.add(pack);
                }
            } catch (IOException ignored) {}
        }
        out.sort(Comparator.comparing(Pack::name));
        return List.copyOf(out);
    }

    private static Pack parse(Path file) {
        try {
            String json = Files.readString(file);
            boolean ci = json.matches("(?s).*\\\"flags\\\"\\s*:\\s*\\\"[^\\\"]*i[^\\\"]*\\\".*");
            ArrayList<String> raw = new ArrayList<>();

            Matcher single = Pattern.compile("\\\"pattern\\\"\\s*:\\s*\\\"((?:\\\\.|[^\\\"])*)\\\"").matcher(json);
            while (single.find()) raw.add(unescape(single.group(1)));

            Matcher array = Pattern.compile("(?s)\\\"patterns\\\"\\s*:\\s*\\[(.*?)]").matcher(json);
            if (array.find()) {
                Matcher item = Pattern.compile("\\\"((?:\\\\.|[^\\\"])*)\\\"").matcher(array.group(1));
                while (item.find()) raw.add(unescape(item.group(1)));
            }

            ArrayList<Pattern> patterns = new ArrayList<>();
            int flags = Pattern.MULTILINE | (ci ? Pattern.CASE_INSENSITIVE : 0);
            for (String r : new LinkedHashSet<>(raw)) {
                try { patterns.add(Pattern.compile(r, flags)); }
                catch (PatternSyntaxException ignored) {}
            }
            String name = file.getFileName().toString().replaceFirst("\\.json$", "");
            return new Pack(name, List.copyOf(patterns));
        } catch (IOException e) {
            return null;
        }
    }

    private static String unescape(String s) {
        return s.replace("\\/", "/")
                .replace("\\\"", "\"")
                .replace("\\n", "\n")
                .replace("\\r", "\r")
                .replace("\\t", "\t")
                .replace("\\\\", "\\");
    }
}
