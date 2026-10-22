package com.victor.reconloop;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Read-only plan catalog shared with reconctl; never interpreted as process arguments. */
final class ReconChainPlan {
    record Row(String stage, String dependencies, String tool, String mode, String output, String detail) {}
    static Map<String, Object> create(String domain) {
        try (var input = ReconChainPlan.class.getResourceAsStream("/chain_catalog.json")) {
            if (input == null) throw new IllegalStateException("Recon chain catalog is missing from the JAR.");
            var plan = Json.asObject(Json.parseStrict(new String(input.readAllBytes(), StandardCharsets.UTF_8)));
            if (plan == null || !"PLAN_ONLY".equals(plan.get("state"))) throw new IllegalStateException("Invalid recon catalog.");
            plan.put("domain", DomainReconProcess.domain(domain)); return plan;
        } catch (IOException e) { throw new IllegalStateException("Cannot read recon chain catalog.", e); }
    }
    static List<Row> rows(Map<String, Object> plan) {
        List<Row> rows = new ArrayList<>();
        for (Object value : Objects.requireNonNull(Json.asArray(plan.get("stages")))) {
            var stage = Json.asObject(value);
            var dependencies = Json.asArray(stage.get("depends_on")).stream().map(Object::toString).toList();
            for (Object item : Json.asArray(stage.get("tools"))) {
                var tool = Json.asObject(item);
                rows.add(new Row(Json.str(stage, "id"), String.join(", ", dependencies), Json.str(tool, "name"),
                        Json.str(tool, "mode"), Json.str(stage, "output"), Json.str(tool, "detail")));
            }
        }
        return List.copyOf(rows);
    }
}
