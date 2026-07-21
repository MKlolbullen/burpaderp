package com.victor.reconloop;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * Multi-vendor LLM provider definitions for on-demand analysis (e.g. JavaScript / source-map review,
 * finding triage). Each provider is called over raw HTTPS — no vendor SDK is bundled — so the
 * extension stays a single lightweight jar and the provider set is easy to extend.
 *
 * <p>API keys resolve from an in-memory UI field or the named environment variable; they are never
 * persisted and calls go direct (not through Burp), so keys never enter the proxy history.
 */
enum LlmProvider {

    ANTHROPIC("Anthropic (Claude)", "claude-opus-4-8", "ANTHROPIC_API_KEY", "text"),
    OPENAI("OpenAI", "gpt-4o", "OPENAI_API_KEY", "content"),
    XAI("xAI (Grok)", "grok-2-latest", "XAI_API_KEY", "content"),
    GEMINI("Google Gemini", "gemini-1.5-pro", "GEMINI_API_KEY", "text");

    private final String label;
    private final String defaultModel;
    private final String envVar;
    private final String responseField;

    LlmProvider(String label, String defaultModel, String envVar, String responseField) {
        this.label = label;
        this.defaultModel = defaultModel;
        this.envVar = envVar;
        this.responseField = responseField;
    }

    String label() { return label; }
    String defaultModel() { return defaultModel; }
    String envVar() { return envVar; }
    /** JSON field carrying the assistant's text in this provider's response. */
    String responseField() { return responseField; }

    String endpoint(String model, String apiKey) {
        return switch (this) {
            case ANTHROPIC -> "https://api.anthropic.com/v1/messages";
            case OPENAI -> "https://api.openai.com/v1/chat/completions";
            case XAI -> "https://api.x.ai/v1/chat/completions";
            case GEMINI -> "https://generativelanguage.googleapis.com/v1beta/models/"
                    + URLEncoder.encode(model, StandardCharsets.UTF_8)
                    + ":generateContent?key=" + URLEncoder.encode(apiKey, StandardCharsets.UTF_8);
        };
    }

    /** Header name/value pairs for the request (Gemini authenticates via the URL, so no auth header). */
    String[][] headers(String apiKey) {
        return switch (this) {
            case ANTHROPIC -> new String[][]{
                    {"content-type", "application/json"},
                    {"x-api-key", apiKey},
                    {"anthropic-version", "2023-06-01"}};
            case OPENAI, XAI -> new String[][]{
                    {"content-type", "application/json"},
                    {"authorization", "Bearer " + apiKey}};
            case GEMINI -> new String[][]{
                    {"content-type", "application/json"}};
        };
    }

    String requestBody(String model, String system, String prompt, int maxTokens) {
        String sys = jsonEscape(system == null ? "" : system);
        String usr = jsonEscape(prompt == null ? "" : prompt);
        String mdl = jsonEscape(model);
        return switch (this) {
            case ANTHROPIC -> "{\"model\":\"" + mdl + "\",\"max_tokens\":" + maxTokens
                    + ",\"system\":\"" + sys + "\",\"messages\":[{\"role\":\"user\",\"content\":\"" + usr + "\"}]}";
            case OPENAI, XAI -> "{\"model\":\"" + mdl + "\",\"max_tokens\":" + maxTokens
                    + ",\"messages\":[{\"role\":\"system\",\"content\":\"" + sys + "\"},"
                    + "{\"role\":\"user\",\"content\":\"" + usr + "\"}]}";
            case GEMINI -> "{\"systemInstruction\":{\"parts\":[{\"text\":\"" + sys + "\"}]},"
                    + "\"contents\":[{\"parts\":[{\"text\":\"" + usr + "\"}]}],"
                    + "\"generationConfig\":{\"maxOutputTokens\":" + maxTokens + "}}";
        };
    }

    static String jsonEscape(String value) {
        StringBuilder out = new StringBuilder(value.length() + 16);
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                case '\b' -> out.append("\\b");
                case '\f' -> out.append("\\f");
                default -> {
                    if (c < 0x20) out.append(String.format("\\u%04x", (int) c));
                    else out.append(c);
                }
            }
        }
        return out.toString();
    }
}
