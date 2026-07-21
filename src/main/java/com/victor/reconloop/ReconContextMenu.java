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
 * with a task-specific system prompt and runs it — no copy-paste.
 */
final class ReconContextMenu implements ContextMenuItemsProvider {

    private static final int MAX_MESSAGE_CHARS = 60_000;

    private final ReconPanel panel;

    ReconContextMenu(ReconPanel panel) {
        this.panel = panel;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        String selection = selectedText(event);
        HttpRequestResponse selected = selected(event);
        if (selection == null && selected == null) return null;

        JMenu menu = new JMenu("Recon Hound: AI analysis");
        if (selection != null) {
            menu.add(fixedItem("Analyze selected text", selection, LlmClient.DEFAULT_JS_SYSTEM_PROMPT));
            menu.add(fixedItem("Selected text: suggest exploitation & chaining", selection, LlmClient.CHAIN_SYSTEM_PROMPT));
            if (selected != null) menu.addSeparator();
        }
        if (selected != null) {
            menu.add(item("Explain request/response & attack surface", selected, LlmClient.REQUEST_ANALYSIS_SYSTEM_PROMPT));
            menu.add(item("Find vulnerabilities", selected, LlmClient.DEFAULT_JS_SYSTEM_PROMPT));
            menu.add(item("Suggest exploitation & chaining", selected, LlmClient.CHAIN_SYSTEM_PROMPT));
        }

        List<Component> items = new ArrayList<>();
        items.add(menu);
        return items;
    }

    private JMenuItem item(String label, HttpRequestResponse rr, String systemPreset) {
        JMenuItem menuItem = new JMenuItem(label);
        menuItem.addActionListener(e -> panel.sendToAi(format(rr), systemPreset));
        return menuItem;
    }

    private JMenuItem fixedItem(String label, String text, String systemPreset) {
        JMenuItem menuItem = new JMenuItem(label);
        menuItem.addActionListener(e -> panel.sendToAi(text, systemPreset));
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
        String message = response
                ? (rr.hasResponse() && rr.response() != null ? rr.response().toString() : null)
                : (rr.request() != null ? rr.request().toString() : null);
        if (message == null) return null;

        int start = Math.max(0, range.get().startIndexInclusive());
        int end = Math.min(message.length(), range.get().endIndexExclusive());
        if (end <= start) return null;
        return message.substring(start, end);
    }

    private static HttpRequestResponse selected(ContextMenuEvent event) {
        if (event.messageEditorRequestResponse().isPresent()) {
            return event.messageEditorRequestResponse().get().requestResponse();
        }
        List<HttpRequestResponse> selected = event.selectedRequestResponses();
        return selected.isEmpty() ? null : selected.get(0);
    }

    private static String format(HttpRequestResponse rr) {
        StringBuilder builder = new StringBuilder();
        if (rr.request() != null) {
            builder.append("=== REQUEST ===\n").append(trim(rr.request().toString())).append("\n\n");
        }
        if (rr.hasResponse() && rr.response() != null) {
            builder.append("=== RESPONSE ===\n").append(trim(rr.response().toString()));
        }
        return builder.toString();
    }

    private static String trim(String value) {
        return value.length() <= MAX_MESSAGE_CHARS ? value : value.substring(0, MAX_MESSAGE_CHARS) + "\n...[truncated]";
    }
}
