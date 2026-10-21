package com.victor.reconloop;

/** Unsupported producers cannot acquire a target dispatch capability. No opt-in bypass exists. */
final class ExternalTargetEgress {
    private ExternalTargetEgress() {}

    static String blocked(String producer) {
        return producer + " is disabled: target requests cannot yet be enforced by the shared outbound gateway (#44).";
    }
}
