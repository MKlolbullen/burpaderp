package com.victor.reconloop;

import burp.api.montoya.persistence.PersistedObject;
import org.junit.Test;

import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;

public class PersistedStateTest {

    @Test
    public void roundTripsFindingTriageVerdict() {
        Map<String, String> values = new HashMap<>();
        PersistedObject store = fakeStore(values);
        ReconModel.FindingRow row = new ReconModel.FindingRow(
                "HIGH", "regex", "AWS key", "response", "AKIA…REDACTED", "https://example.test/app.js",
                "LIKELY_TP");

        PersistedState.saveFindings(store, List.of(row));
        List<ReconModel.FindingRow> restored = PersistedState.loadFindings(store);

        assertEquals(1, restored.size());
        assertEquals("LIKELY_TP", restored.getFirst().triage());
    }

    @Test
    public void loadsLegacySixFieldRowsWithEmptyTriage() {
        Map<String, String> values = new HashMap<>();
        values.put(PersistedState.K_FINDINGS,
                "MEDIUM\thygiene\tWeak CSP\tresponse\tunsafe-inline\thttps://example.test/");
        PersistedObject store = fakeStore(values);

        List<ReconModel.FindingRow> restored = PersistedState.loadFindings(store);

        assertEquals(1, restored.size());
        assertEquals("", restored.getFirst().triage());
    }

    private static PersistedObject fakeStore(Map<String, String> values) {
        return (PersistedObject) Proxy.newProxyInstance(
                PersistedObject.class.getClassLoader(),
                new Class<?>[]{PersistedObject.class},
                (proxy, method, args) -> switch (method.getName()) {
                    case "setString" -> {
                        values.put((String) args[0], (String) args[1]);
                        yield null;
                    }
                    case "getString" -> values.get((String) args[0]);
                    case "toString" -> "FakePersistedObject";
                    case "hashCode" -> System.identityHashCode(proxy);
                    case "equals" -> proxy == args[0];
                    default -> throw new UnsupportedOperationException(method.getName());
                });
    }
}
