package com.victor.reconloop;

import burp.api.montoya.core.Range;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import org.junit.Test;
import javax.swing.*;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import static org.junit.Assert.*;

public class ReconContextMenuTest {
    private static ContextMenuEvent event(List<HttpRequestResponse> pairs, MessageEditorHttpRequestResponse editor) {
        return FakeMontoya.proxy(ContextMenuEvent.class, (self, method, args) -> switch (method.getName()) {
            case "messageEditorRequestResponse" -> Optional.ofNullable(editor);
            case "selectedRequestResponses" -> pairs;
            default -> null;
        });
    }

    @Test public void contextActionStagesEverySelectedExchangeWithoutNetworkOrIssuePublishing() throws Exception {
        try (var fake = new FakeMontoya()) {
            var first = FakeMontoya.pair(fake.request("https://example.test/a"), FakeMontoya.response(200, "a response", Map.of()));
            var second = FakeMontoya.pair(fake.request("https://example.test/app.js"), FakeMontoya.response(200, "const x=1;", Map.of()));
            AtomicReference<List<AiAnalysis.Source>> staged = new AtomicReference<>();
            var provider = new ReconContextMenu((sources, focus) -> staged.set(sources));
            SwingUtilities.invokeAndWait(() -> {
                JMenu menu = (JMenu) provider.provideMenuItems(event(List.of(first, second), null)).getFirst();
                assertNull(staged.get()); menu.getItem(1).doClick();
            });
            assertEquals(2, staged.get().size());
            assertTrue(staged.get().getFirst().text().contains("=== REQUEST ==="));
            assertTrue(staged.get().getFirst().text().contains("=== RESPONSE ==="));
            assertTrue(staged.get().getLast().text().contains("const x=1;"));
            assertTrue(fake.sent.isEmpty()); assertTrue(fake.issues.isEmpty());
        }
    }

    @Test public void largeMessagesAreVisiblyTruncatedWithinTheSourceBudget() {
        try (var fake = new FakeMontoya()) {
            var pair = FakeMontoya.pair(fake.request("https://example.test/a"), FakeMontoya.response(200, "x".repeat(60_000), Map.of()));
            String formatted = ReconContextMenu.format(pair);
            assertTrue(formatted.contains("[truncated]")); assertTrue(formatted.length() < AiAnalysis.MAX_SOURCE_CHARS);
        }
    }

    @Test public void oversizedSelectionsAreDisabledAndEmptySelectionsHaveNoMenu() throws Exception {
        try (var fake = new FakeMontoya()) {
            var pair = FakeMontoya.pair(fake.request("https://example.test/a"), FakeMontoya.response(200, "a", Map.of()));
            var provider = new ReconContextMenu((sources, focus) -> fail("Must not stage an oversized batch"));
            SwingUtilities.invokeAndWait(() -> {
                JMenu menu = (JMenu) provider.provideMenuItems(event(java.util.Collections.nCopies(13, pair), null)).getFirst();
                assertFalse(menu.getItem(0).isEnabled());
                assertNull(provider.provideMenuItems(event(List.of(), null)));
            });
        }
    }

    @Test public void editorSelectionOffsetsAreBytesEvenWhenEarlierTextIsUtf8() throws Exception {
        try (var fake = new FakeMontoya()) {
            var pair = FakeMontoya.pair(fake.request("https://example.test/a"), FakeMontoya.response(200, "π TARGET suffix", Map.of()));
            byte[] bytes = pair.response().toByteArray().getBytes();
            String all = new String(bytes, java.nio.charset.StandardCharsets.UTF_8);
            int start = all.substring(0, all.indexOf("TARGET")).getBytes(java.nio.charset.StandardCharsets.UTF_8).length;
            Range range = FakeMontoya.proxy(Range.class, (self, method, args) -> switch (method.getName()) {
                case "startIndexInclusive" -> start;
                case "endIndexExclusive" -> start + 6;
                default -> null;
            });
            var editor = FakeMontoya.proxy(MessageEditorHttpRequestResponse.class, (self, method, args) -> switch (method.getName()) {
                case "selectionOffsets" -> Optional.of(range);
                case "selectionContext" -> MessageEditorHttpRequestResponse.SelectionContext.RESPONSE;
                case "requestResponse" -> pair;
                default -> null;
            });
            AtomicReference<List<AiAnalysis.Source>> staged = new AtomicReference<>();
            SwingUtilities.invokeAndWait(() -> {
                var provider = new ReconContextMenu((sources, focus) -> staged.set(sources));
                ((JMenu) provider.provideMenuItems(event(List.of(), editor)).getFirst()).getItem(0).doClick();
            });
            assertEquals("TARGET", staged.get().getFirst().text());
        }
    }
}
