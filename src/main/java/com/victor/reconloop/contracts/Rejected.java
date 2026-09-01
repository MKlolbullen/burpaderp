package com.victor.reconloop.contracts;

/** Quarantine record for anything that failed a contract. */
public record Rejected(String schema, String reason, String raw, String source) {
    public Rejected {
        schema = schema == null ? "" : schema;
        reason = reason == null ? "unknown" : reason;
        raw = raw == null ? "" : raw;
        source = source == null ? "" : source;
    }
}
