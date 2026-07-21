package com.victor.reconloop;

import java.io.IOException;
import java.nio.file.*;
import java.util.*;

final class PayloadLibrary {
    private final Map<String, List<String>> payloads;

    PayloadLibrary() {
        this(findPayloadDirectory());
    }

    PayloadLibrary(Path directory) {
        this.payloads = load(directory);
    }

    Set<String> categories() { return payloads.keySet(); }
    List<String> get(String category) { return payloads.getOrDefault(category, List.of()); }
    int totalPayloads() { return payloads.values().stream().mapToInt(List::size).sum(); }

    private static Path findPayloadDirectory() {
        String env = System.getenv("RECON_HOUND_PAYLOADS");
        if (env != null && !env.isBlank() && Files.isDirectory(Path.of(env))) return Path.of(env);
        for (Path p : List.of(
                Path.of("payloads"),
                Path.of(System.getProperty("user.home"), ".recon-hound", "payloads"),
                Path.of(System.getProperty("user.home"), "payloads")
        )) if (Files.isDirectory(p)) return p;
        return Path.of("payloads");
    }

    private static Map<String, List<String>> load(Path dir) {
        TreeMap<String, List<String>> out = new TreeMap<>();
        if (!Files.isDirectory(dir)) return Collections.unmodifiableMap(out);
        try (DirectoryStream<Path> files = Files.newDirectoryStream(dir, "*.txt")) {
            for (Path file : files) {
                ArrayList<String> lines = new ArrayList<>();
                for (String line : Files.readAllLines(file)) {
                    if (!line.isBlank() && !line.stripLeading().startsWith("#")) lines.add(line);
                }
                String name = file.getFileName().toString().replaceFirst("\\.txt$", "");
                out.put(name, List.copyOf(lines));
            }
        } catch (IOException ignored) {}
        return Collections.unmodifiableMap(out);
    }
}
