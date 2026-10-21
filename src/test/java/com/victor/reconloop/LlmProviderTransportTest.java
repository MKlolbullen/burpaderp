package com.victor.reconloop;

import org.junit.Test;
import java.net.http.HttpRequest;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Flow;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import static org.junit.Assert.*;

public class LlmProviderTransportTest {
    @Test public void allProvidersHaveIndependentKeyAndModelEnvironmentVariables() {
        for (LlmProvider p : LlmProvider.values()) {
            assertEquals(p.name() + "_API_KEY", p.envVar());
            assertEquals(p.name() + "_MODEL", p.modelEnvVar());
            assertEquals("account-model", p.configuredModel(key -> " account-model "));
            assertEquals(p.defaultModel(), p.configuredModel(key -> ""));
            assertEquals(p.defaultModel(), p.configuredModel(key -> null));
        }
    }

    @Test public void endpointsRemainFixedHttpsOriginsAndKeysNeverEnterUrls() {
        Map<LlmProvider, String> hosts = Map.of(LlmProvider.OPENAI, "api.openai.com", LlmProvider.ANTHROPIC, "api.anthropic.com",
                LlmProvider.XAI, "api.x.ai", LlmProvider.VENICE, "api.venice.ai", LlmProvider.GEMINI, "generativelanguage.googleapis.com");
        for (var provider : LlmProvider.values()) {
            AtomicReference<HttpRequest> captured = new AtomicReference<>();
            LlmClient client = new LlmClient(request -> { captured.set(request); return new LlmClient.Reply(401, "NEVER SHOW THIS BODY"); });
            String result = client.complete(provider, "../../other?key=attack", "FAKE-KEY-ONLY", "system", "user");
            assertTrue(result.startsWith("[HTTP 401]")); assertFalse(result.contains("NEVER SHOW"));
            var request = captured.get(); assertEquals(hosts.get(provider), request.uri().getHost());
            assertEquals("https", request.uri().getScheme()); assertNull(request.uri().getRawQuery());
            assertFalse(request.uri().toString().contains("FAKE-KEY-ONLY"));
            assertTrue(request.headers().map().values().stream().flatMap(List::stream).anyMatch(v -> v.contains("FAKE-KEY-ONLY")));
        }
    }

    @Test public void openAiUsesCompletionTokenBudgetWhileOtherChatProvidersKeepTheirShape() {
        var openai = Json.asObject(Json.parseStrict(LlmProvider.OPENAI.requestBody("m", "sys", "usr", 4096)));
        assertEquals(4096, ((Number) openai.get("max_completion_tokens")).intValue()); assertFalse(openai.containsKey("max_tokens"));
        for (var p : List.of(LlmProvider.XAI, LlmProvider.VENICE)) {
            assertTrue(Json.asObject(Json.parseStrict(p.requestBody("m", "sys", "usr", 4096))).containsKey("max_tokens"));
        }
    }

    @Test public void chatParsingIgnoresMetadataReasoningAndOtherChoices() {
        String body = "{\"content\":\"metadata\",\"choices\":[{\"finish_reason\":\"stop\",\"message\":{\"reasoning_content\":\"private thoughts\",\"content\":\"answer\"}},"
                + "{\"message\":{\"content\":\"other choice\"}}]}";
        for (var p : List.of(LlmProvider.OPENAI, LlmProvider.XAI, LlmProvider.VENICE)) assertEquals("answer", p.assistantText(body));
    }

    @Test public void anthropicParsingJoinsTextBlocksWithoutThinkingOrToolCalls() {
        assertEquals("ab", LlmProvider.ANTHROPIC.assistantText("{\"stop_reason\":\"end_turn\",\"content\":["
                + "{\"type\":\"thinking\",\"text\":\"secret\"},{\"type\":\"text\",\"text\":\"a\"},"
                + "{\"type\":\"tool_use\",\"text\":\"run\"},{\"type\":\"text\",\"text\":\"b\"}]}"));
    }

    @Test public void geminiParsingIgnoresThoughtPartsAndJoinsAnswerParts() {
        String raw = "{\"text\":\"metadata\",\"candidates\":[{\"finishReason\":\"STOP\",\"content\":{\"parts\":["
                + "{\"thought\":true,\"text\":\"private thoughts\"},{\"text\":\"a\"},{\"text\":\"b\"}]}}]}";
        assertEquals("ab", LlmProvider.GEMINI.assistantText(raw));
    }

    @Test public void truncatedBlockedAndToolResponsesAreNotMistakenForCompletedAnalysis() {
        assertNull(LlmProvider.OPENAI.assistantText("{\"choices\":[{\"finish_reason\":\"length\",\"message\":{\"content\":\"partial\"}}]}"));
        assertNull(LlmProvider.ANTHROPIC.assistantText("{\"stop_reason\":\"max_tokens\",\"content\":[{\"type\":\"text\",\"text\":\"partial\"}]}"));
        assertNull(LlmProvider.GEMINI.assistantText("{\"candidates\":[{\"finishReason\":\"SAFETY\",\"content\":{\"parts\":[{\"text\":\"partial\"}]}}]}"));
        assertNull(LlmProvider.OPENAI.assistantText("{\"error\":{\"content\":\"do not show\"}}"));
    }

    @Test public void malformedProviderEnvelopeDoesNotLeakItsBodyOrExceptionDetails() {
        LlmClient client = new LlmClient(r -> new LlmClient.Reply(200, "FAKE-SECRET-NOT-JSON"));
        String result = client.complete(LlmProvider.OPENAI, "m", "key", "s", "p");
        assertTrue(result.startsWith("[error]")); assertFalse(result.contains("FAKE-SECRET"));
        client = new LlmClient(r -> { throw new IllegalArgumentException("secret-key-in-exception"); });
        assertFalse(client.complete(LlmProvider.OPENAI, "m", "key", "s", "p").contains("secret-key-in-exception"));
    }

    @Test public void interruptStopsTheRequestAndPreservesCancellationForTheNextProvider() {
        LlmClient client = new LlmClient(r -> { throw new InterruptedException(); });
        try {
            assertTrue(client.complete(LlmProvider.OPENAI, "m", "key", "s", "p").contains("Cancelled"));
            assertTrue(Thread.currentThread().isInterrupted());
            LlmClient never = new LlmClient(r -> { fail("A cancelled worker cannot start another request"); return null; });
            assertTrue(never.complete(LlmProvider.VENICE, "m", "key", "s", "p").contains("Cancelled"));
        } finally { Thread.interrupted(); }
    }

    @Test public void blankCredentialsDoNotInvokeTransportAndRecordStringsHideKeys() {
        LlmClient client = new LlmClient(r -> { fail("Missing key must not send"); return null; });
        assertTrue(client.complete(LlmProvider.OPENAI, "m", "", "s", "p").startsWith("[error]"));
        assertFalse(new LlmClient.LlmCredential(LlmProvider.OPENAI, "m", "PRIVATEKEY").toString().contains("PRIVATEKEY"));
    }

    @Test public void providerBodySubscriberCancelsBeforeBufferingAnOversizedChunk() {
        var body = new LlmClient.LimitedBody(); AtomicBoolean cancelled = new AtomicBoolean();
        body.onSubscribe(new Flow.Subscription() {
            public void request(long n) {}
            public void cancel() { cancelled.set(true); }
        });
        body.onNext(List.of(ByteBuffer.wrap(new byte[LlmClient.LimitedBody.LIMIT + 1])));
        assertTrue(cancelled.get()); assertTrue(body.getBody().toCompletableFuture().isCompletedExceptionally());
    }

    @Test public void providerBodySubscriberHandlesUtf8AcrossBufferBoundaries() {
        var body = new LlmClient.LimitedBody();
        body.onSubscribe(new Flow.Subscription() { public void request(long n) {} public void cancel() {} });
        byte[] bytes = "π".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        body.onNext(List.of(ByteBuffer.wrap(new byte[]{bytes[0]}))); body.onNext(List.of(ByteBuffer.wrap(new byte[]{bytes[1]})));
        body.onComplete(); assertEquals("π", body.getBody().toCompletableFuture().join());
    }
}
