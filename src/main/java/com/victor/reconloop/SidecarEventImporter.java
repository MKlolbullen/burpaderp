package com.victor.reconloop;

import java.io.IOException;
import java.io.Reader;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.function.Consumer;

/**
 * Bounded JSONL importer for Go-sidecar records.
 *
 * <p>Invalid, over-sized, out-of-scope, and not-yet-materializable records are rejected individually
 * so one bad line cannot silently discard the rest of an external tool's results.
 */
final class SidecarEventImporter {
    static final int MAX_LINE_CHARS = 1 << 20;
    static final int MAX_RECORDS = 100_000;

    @FunctionalInterface
    interface ScopeValidator {
        boolean allows(SidecarEvent.Event event);
    }

    record ImportResult(int accepted, int rejected, List<String> rejectionReasons) {
        ImportResult {
            rejectionReasons = rejectionReasons == null ? List.of() : List.copyOf(rejectionReasons);
        }
    }

    private record ReadLine(String value, boolean oversized) {}

    private SidecarEventImporter() {}

    static ImportResult importJsonl(Reader input, ScopeValidator scope, Consumer<SidecarEvent.Event> accepted)
            throws IOException {
        Objects.requireNonNull(input, "input");
        Objects.requireNonNull(scope, "scope");
        Objects.requireNonNull(accepted, "accepted");
        int acceptedCount = 0;
        int rejectedCount = 0;
        List<String> reasons = new ArrayList<>();
        int lineNo = 0;
        ReadLine line;
        while ((line = readBoundedLine(input, MAX_LINE_CHARS)) != null) {
            lineNo++;
            if (lineNo > MAX_RECORDS) {
                rejectedCount++;
                reasons.add("record limit exceeded: " + MAX_RECORDS);
                break;
            }
            if (line.oversized()) {
                rejectedCount++;
                reasons.add("line " + lineNo + ": exceeds " + MAX_LINE_CHARS + " characters");
                continue;
            }
            String raw = line.value().strip();
            if (raw.isEmpty()) continue;
            try {
                SidecarEvent.Event event = SidecarEvent.parse(raw);
                if (!event.materializable()) {
                    rejectedCount++;
                    reasons.add("line " + lineNo + ": " + event.kind().name().toLowerCase() + " is not importable into Burp");
                    continue;
                }
                if (!scope.allows(event)) {
                    rejectedCount++;
                    reasons.add("line " + lineNo + ": outside current Burp scope");
                    continue;
                }
                accepted.accept(event);
                acceptedCount++;
            } catch (RuntimeException e) {
                rejectedCount++;
                reasons.add("line " + lineNo + ": " + e.getMessage());
            }
        }
        return new ImportResult(acceptedCount, rejectedCount, reasons);
    }

    private static ReadLine readBoundedLine(Reader input, int maxChars) throws IOException {
        StringBuilder builder = new StringBuilder(Math.min(256, maxChars));
        boolean any = false;
        boolean oversized = false;
        while (true) {
            int value = input.read();
            if (value < 0) return any ? new ReadLine(builder.toString(), oversized) : null;
            any = true;
            if (value == '\n') return new ReadLine(builder.toString(), oversized);
            if (value == '\r') continue;
            if (builder.length() < maxChars) builder.append((char) value);
            else oversized = true;
        }
    }
}
