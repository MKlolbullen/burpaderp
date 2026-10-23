package com.victor.reconloop;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import org.junit.Test;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.*;

public class PersistentPayloadPermissionIntegrationTest {
    private static final String ROOT = "https://api.example.test/search?q=a&r=b";

    private static final class Harness implements AutoCloseable {
        final FakeMontoya fake;
        final ManualExecutor executor = new ManualExecutor();
        final List<String> callbacks = new ArrayList<>();
        final ReconController controller;
        final JCheckBox oast, persistent;

        Harness(FakeMontoya fake) throws Exception {
            this.fake = fake;
            var collaborator = NativeEvidenceIntegrationTest.collaborator(callbacks);
            MontoyaApi api = FakeMontoya.proxy(MontoyaApi.class, (self, method, args) -> {
                if (method.getName().equals("collaborator")) {
                    fake.apiAccesses.add("collaborator");
                    return FakeMontoya.proxy(method.getReturnType(), (factory, call, values) ->
                            call.getName().equals("createClient") ? collaborator : null);
                }
                return method.invoke(fake.api, args);
            });
            var findings = new ReconModel.FindingTableModel();
            var discoveries = new ReconModel.DiscoveryTableModel();
            var parameters = new ReconModel.ParameterTableModel();
            var reflections = new ReconModel.ReflectionTableModel();
            var active = new ReconModel.ActiveTableModel();
            var assets = new ReconModel.AssetTableModel();
            controller = new ReconController(api, findings, discoveries, parameters, reflections, active, assets,
                    executor, false, fake.destinations(), new LlmClient(request -> {
                        throw new AssertionError("Permission controls must not call an LLM");
                    }));
            ReconPanel[] panel = new ReconPanel[1];
            SwingUtilities.invokeAndWait(() -> panel[0] = new ReconPanel(api, controller, findings, discoveries,
                    parameters, reflections, active, assets));
            oast = checkbox(panel[0], "Allow OAST / Collaborator callbacks");
            persistent = checkbox(panel[0], "Allow persistent / stored browser payloads");
            assertNotNull(oast); assertNotNull(persistent);
            fake.siteMap.add(FakeMontoya.pair(fake.request(ROOT), FakeMontoya.response(200, "", Map.of())));
        }

        void click(JCheckBox checkbox) throws Exception { SwingUtilities.invokeAndWait(checkbox::doClick); }
        void grantBoth() throws Exception { click(oast); click(persistent); }
        public void close() { controller.shutdown(); }
    }

    private static JCheckBox checkbox(Component root, String label) {
        if (root instanceof JCheckBox box && label.equals(box.getText())) return box;
        if (root instanceof Container container) for (Component child : container.getComponents()) {
            JCheckBox found = checkbox(child, label);
            if (found != null) return found;
        }
        return null;
    }

    private static void assertPreview(Harness harness, Set<String> missing) {
        String preview = harness.controller.previewActiveTests("blind-xss");
        List<String> rows = preview.lines().filter(line -> line.contains(" | blind-xss | ")).toList();
        assertFalse(preview, rows.isEmpty());
        for (String row : rows) {
            assertTrue(row, row.contains(missing.isEmpty() ? "PENDING_BINDING" : "MISSING_PERMISSION"));
            for (String permission : List.of("OAST", "PERSISTENT_PAYLOAD"))
                assertEquals(row, missing.contains(permission), row.contains(permission));
        }
    }

    @Test public void uiGrantsDefaultOffStayIndependentAndPreviewNeverAllocatesOrSends() throws Exception {
        try (var fake = new FakeMontoya(); var harness = new Harness(fake)) {
            assertFalse(harness.oast.isSelected()); assertFalse(harness.persistent.isSelected());
            assertTrue(harness.persistent.getToolTipText().contains("execute later"));
            fake.apiAccesses.clear();
            assertPreview(harness, Set.of("OAST", "PERSISTENT_PAYLOAD"));
            harness.click(harness.oast);
            assertFalse(harness.persistent.isSelected());
            assertPreview(harness, Set.of("PERSISTENT_PAYLOAD"));
            harness.click(harness.persistent);
            assertPreview(harness, Set.of());
            harness.click(harness.oast);
            assertTrue(harness.persistent.isSelected());
            assertPreview(harness, Set.of("OAST"));
            assertTrue(fake.sent.isEmpty()); assertTrue(fake.dnsLookups.isEmpty());
            assertTrue(harness.callbacks.isEmpty()); assertFalse(fake.apiAccesses.contains("collaborator"));
            assertTrue(fake.errors.toString(), fake.errors.isEmpty());
        }
    }

    @Test public void revokingEitherUiGrantInvalidatesQueuedWorkEvenAfterRegrant() throws Exception {
        for (boolean revokeOast : List.of(false, true)) {
            try (var fake = new FakeMontoya(); var harness = new Harness(fake)) {
                harness.grantBoth(); harness.controller.setActiveTestsEnabled(true);
                harness.controller.runActiveTests();
                JCheckBox revoked = revokeOast ? harness.oast : harness.persistent;
                harness.click(revoked); harness.click(revoked);
                harness.executor.runAll();
                assertTrue(fake.sent.isEmpty()); assertTrue(fake.dnsLookups.isEmpty());
                assertTrue(harness.callbacks.isEmpty());
                assertPreview(harness, Set.of());
                assertTrue(fake.errors.toString(), fake.errors.isEmpty());
            }
        }
    }

    @Test public void revokingEitherUiGrantDuringDispatchStopsTheNextRequestAndRegrantCannotReviveRun() throws Exception {
        for (boolean revokeOast : List.of(false, true)) {
            try (var fake = new FakeMontoya(); var harness = new Harness(fake)) {
                harness.grantBoth(); harness.controller.setActiveTestsEnabled(true);
                harness.controller.setActiveRequestBudget(500);
                harness.controller.setActivePerEndpointBudget(500);
                harness.controller.setActivePerHostBudget(500);
                AtomicInteger beacons = new AtomicInteger();
                fake.onSend = request -> {
                    if (!isBeacon(request)) return;
                    beacons.incrementAndGet();
                    try {
                        JCheckBox revoked = revokeOast ? harness.oast : harness.persistent;
                        harness.click(revoked); harness.click(revoked);
                    } catch (Exception error) { throw new AssertionError(error); }
                };
                harness.controller.runActiveTests(); harness.executor.runAll();
                assertEquals(1, beacons.get());
                assertTrue(isBeacon(fake.sent.getLast()));
                assertTrue(harness.oast.isSelected()); assertTrue(harness.persistent.isSelected());
                assertTrue(fake.errors.toString(), fake.errors.isEmpty());
            }
        }
    }

    private static boolean isBeacon(HttpRequest request) {
        return request.parameters().stream().anyMatch(p -> p.value().contains("<script src=//")
                && p.value().contains(".oast.test"));
    }
}
