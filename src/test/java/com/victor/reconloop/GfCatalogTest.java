package com.victor.reconloop;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import static org.junit.Assert.*;

@RunWith(Parameterized.class)
public class GfCatalogTest {
    private static final GfPatternLoader LOADER = new GfPatternLoader(List.of(), true);
    private final String id;
    private final Map<String, Object> rule;
    public GfCatalogTest(String id, Map<String, Object> rule) { this.id = id; this.rule = rule; }
    @Parameterized.Parameters(name="{0}") public static Collection<Object[]> rules() throws Exception {
        var catalog = Json.asObject(Json.parseStrict(Files.readString(Path.of("gf/catalog.json"))));
        return Json.asArray(catalog.get("rules")).stream().map(Json::asObject)
                .map(r -> new Object[]{r.get("id"), r}).toList();
    }
    static String join(Object parts) { return Json.asArray(parts).stream().map(String.class::cast).reduce("", String::concat); }
    @Test public void extractsTheWholeValueWithExactOffsetsInRealisticContexts() {
        assertEquals(List.of(), LOADER.diagnostics());
        for (Object raw : Json.asArray(rule.get("positive"))) {
            var sample = Json.asObject(raw); String value = join(sample.get("valueParts"));
            String text = sample.get("prefix") + value + sample.get("suffix");
            var matched = LOADER.scan(text).stream().filter(m -> m.ruleId().equals(id) && m.value().equals(value)).findFirst();
            assertTrue("Expected whole-value detection: " + id, matched.isPresent());
            var match = matched.orElseThrow();
            assertEquals(value, text.substring(match.start(), match.end()));
            assertEquals(rule.get("category"), match.category());
        }
    }
    @Test public void rejectsNegativeFixturesIncludingNativeValidationAndEntropyCases() {
        for (Object raw : Json.asArray(rule.get("negative"))) {
            String text = join(Json.asObject(raw).get("parts"));
            assertFalse("Unexpected detection: " + id, LOADER.scan(text).stream().anyMatch(m -> m.ruleId().equals(id)));
        }
    }
}
