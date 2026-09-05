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

    ANTHROPIC("Anthropic (Claude)", "claude-opus-5", "ANTHROPIC_API_KEY", "text"),
    OPENAI("OpenAI", "gpt-4o", "OPENAI_API_KEY", "content"),
    XAI("xAI (Grok)", "grok-2-latest", "XAI_API_KEY", "content"),
    GEMINI("Google Gemini", "gemini-1.5-pro", "GEMINI_API_KEY", "text"),
    /** Venice.ai provider for uncensored content generation that mainstream models refuse. */
    VENICE("Venice.ai", "venice-uncensored", "VENICE_API_KEY", "content");

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
            case VENICE -> "https://api.venice.ai/api/v1/chat/completions";
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
            case OPENAI, XAI, VENICE -> new String[][]{
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
            case ANTHROPIC -> {
                // Emit the system prompt as a cached content block so a repeated stable prefix (large
                // static system prompt, or an inventory hoisted into `system`) is billed once and read
                // from cache on subsequent calls. Prompt caching is GA — no beta header — and if the
                // prefix is below the model's minimum cacheable size the field is simply ignored, so
                // this is safe for short prompts. An empty system stays a plain "" to avoid an empty
                // cached block.
                String systemJson = (system == null || system.isBlank())
                        ? "\"\""
                        : "[{\"type\":\"text\",\"text\":\"" + sys + "\",\"cache_control\":{\"type\":\"ephemeral\"}}]";
                yield "{\"model\":\"" + mdl + "\",\"max_tokens\":" + maxTokens
                        + ",\"system\":" + systemJson
                        + ",\"messages\":[{\"role\":\"user\",\"content\":\"" + usr + "\"}]}";
            }
            case OPENAI, XAI, VENICE -> "{\"model\":\"" + mdl + "\",\"max_tokens\":" + maxTokens
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
