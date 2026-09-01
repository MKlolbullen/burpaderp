package com.victor.reconloop.contracts;

public record ContractResult<T>(T value, Rejected rejected) {
    public boolean accepted() {
        return value != null && rejected == null;
    }

    public static <T> ContractResult<T> ok(T value) {
        if (value == null) throw new IllegalArgumentException("accepted value must be non-null");
        return new ContractResult<>(value, null);
    }

    public static <T> ContractResult<T> reject(String schema, String reason, String raw, String source) {
        return new ContractResult<>(null, new Rejected(schema, reason, raw, source));
    }
}
