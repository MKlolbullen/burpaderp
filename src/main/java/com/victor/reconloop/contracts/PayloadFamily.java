package com.victor.reconloop.contracts;

/**
 * Payload families that the router may attach to a parameterized URL.
 * Names align with {@code payloads/manifest.json} plus profiler classes.
 */
public enum PayloadFamily {
    XSS,
    SQLI,
    SSTI,
    LFI,
    RCE,
    SSRF,
    OPEN_REDIRECT,
    CRLF,
    IDOR,
    GRAPHQL,
    JWT,
    GENERIC
}
