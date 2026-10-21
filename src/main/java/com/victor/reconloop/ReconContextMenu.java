package com.victor.reconloop;

import burp.api.montoya.core.Range;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;

import javax.swing.*;
import java.awt.Component;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Adds a "Recon Hound: AI analysis" submenu to Burp's right-click menu (Proxy history, site map,
 * Repeater, etc.). Each item ships the selected request/response into the extension's AI analysis tab
 * for local preview. The user explicitly selects providers and sends from the tab.
 */
final class ReconContextMenu implements ContextMenuItemsProvider {

    private static final int MAX_MESSAGE_CHARS = 23_000;

    private final java.util.function.BiConsumer<List<AiAnalysis.Source>, String> stage;

    ReconContextMenu(ReconPanel panel) {
        this(panel::stageAiSources);
    }

    ReconContextMenu(java.util.function.BiConsumer<List<AiAnalysis.Source>, String> stage) {
        this.stage = stage;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        String selection = selectedText(event);
        List<HttpRequestResponse> selected = selected(event);
        if (selection == null && selected.isEmpty()) return null;

        JMenu menu = new JMenu("Recon Hound: AI analysis");
        if (selection != null) {
            menu.add(fixedItem("Stage selected text for review", trim(selection), "Review this selected text for potential vulnerabilities."));
            menu.add(fixedItem("Stage selected text: PoC / chain suggestions", trim(selection), "Suggest manual PoCs and possible chains, stating assumptions."));
            if (!selected.isEmpty()) menu.addSeparator();
        }
        if (!selected.isEmpty()) {
            menu.add(item("Stage exchanges: explain attack surface", selected, "Explain the endpoints and attacker-controlled fields; distinguish observations from assumptions."));
            menu.add(item("Stage exchanges: find vulnerabilities", selected, "Review for vulnerabilities including XSS, CSRF, SSRF, secrets, access control and injection."));
            menu.add(item("Stage exchanges: suggest manual PoCs / chains", selected, "Suggest manual PoCs and possible chains, stating preconditions and missing evidence."));
        }

        List<Component> items = new ArrayList<>();
        items.add(menu);
        return items;
    }

    private JMenuItem item(String label, List<HttpRequestResponse> exchanges, String systemPreset) {
        JMenuItem menuItem = new JMenuItem(label);
        menuItem.setEnabled(exchanges.size() <= AiAnalysis.MAX_SOURCES);
        menuItem.setToolTipText("Stage captured traffic locally; select at most 12 exchanges. Nothing is sent to a provider yet.");
        menuItem.addActionListener(e -> {
            List<AiAnalysis.Source> sources = new ArrayList<>();
            for (var rr : exchanges) {
                String name = rr.request() == null ? "Captured exchange" : rr.request().url();
                if (name.length() > 300) name = name.substring(0, 300);
                sources.add(new AiAnalysis.Source("s" + (sources.size() + 1), AiAnalysis.Kind.HTTP_EXCHANGE, name, format(rr)));
            }
            stage.accept(sources, systemPreset);
        });
        return menuItem;
    }

    private JMenuItem fixedItem(String label, String text, String systemPreset) {
        JMenuItem menuItem = new JMenuItem(label);
        menuItem.addActionListener(e -> stage.accept(List.of(
                new AiAnalysis.Source("s1", AiAnalysis.Kind.TEXT, "Selected text", text)), systemPreset));
        return menuItem;
    }

    /** Returns the user's highlighted substring within the message editor, or null if none. */
    private static String selectedText(ContextMenuEvent event) {
        Optional<MessageEditorHttpRequestResponse> editor = event.messageEditorRequestResponse();
        if (editor.isEmpty()) return null;
        MessageEditorHttpRequestResponse editorRr = editor.get();
        Optional<Range> range = editorRr.selectionOffsets();
        if (range.isEmpty()) return null;

        boolean response = editorRr.selectionContext() == MessageEditorHttpRequestResponse.SelectionContext.RESPONSE;
        HttpRequestResponse rr = editorRr.requestResponse();
        byte[] message = response
                ? (rr.hasResponse() && rr.response() != null ? rr.response().toByteArray().getBytes() : null)
                : (rr.request() != null ? rr.request().toByteArray().getBytes() : null);
        if (message == null) return null;

        int start = Math.max(0, range.get().startIndexInclusive());
        int end = Math.min(message.length, range.get().endIndexExclusive());
        if (end <= start) return null;
        return trim(new String(message, start, end - start, java.nio.charset.StandardCharsets.UTF_8).replace('\0', ' '));
    }

    private static List<HttpRequestResponse> selected(ContextMenuEvent event) {
        if (event.messageEditorRequestResponse().isPresent()) {
            return List.of(event.messageEditorRequestResponse().get().requestResponse());
        }
        List<HttpRequestResponse> selected = event.selectedRequestResponses();
        return List.copyOf(selected);
    }

    static String format(HttpRequestResponse rr) {
        StringBuilder builder = new StringBuilder();
        if (rr.request() != null) {
            builder.append("=== REQUEST ===\n").append(trim(rr.request().toString())).append("\n\n");
        }
        if (rr.hasResponse() && rr.response() != null) {
            builder.append("=== RESPONSE ===\n").append(trim(rr.response().toString()));
        }
        return builder.toString().replace('\0', ' ');
    }

    private static String trim(String value) {
        return value.length() <= MAX_MESSAGE_CHARS ? value : value.substring(0, MAX_MESSAGE_CHARS) + "\n...[truncated]";
    }
}
