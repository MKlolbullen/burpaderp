package com.victor.reconloop;

import burp.api.montoya.persistence.PersistedObject;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

/**
 * Serialises Recon Hound's cross-session state into Burp's project-scoped
 * {@link PersistedObject} (extension data): the issue-dedupe keys, the host/IP asset inventory, and
 * the Findings / Hosts table rows. This lets a reopened project (or a reloaded extension) restore the
 * plugin's results and, crucially, avoid re-filing findings it already reported.
 *
 * <p>Storage is newline-delimited records with tab-separated fields; field values are sanitised of
 * tabs/newlines on write. Dependency-free.
 */
final class PersistedState {
    static final String K_FILED = "reconhound.filed";
    static final String K_HOSTS = "reconhound.hosts";
    static final String K_IPS = "reconhound.ips";
    static final String K_FINDINGS = "reconhound.findings";
    static final String K_ASSETS = "reconhound.assets";

    static void saveStrings(PersistedObject store, String key, Collection<String> values) {
        store.setString(key, String.join("\n", values));
    }

    static List<String> loadStrings(PersistedObject store, String key) {
        String value = store.getString(key);
        if (value == null || value.isBlank()) return List.of();
        return new ArrayList<>(Arrays.asList(value.split("\n", -1)));
    }

    static void saveFindings(PersistedObject store, List<ReconModel.FindingRow> rows) {
        StringBuilder out = new StringBuilder();
        for (ReconModel.FindingRow r : rows) {
            if (out.length() > 0) out.append('\n');
            out.append(join(r.severity(), r.provider(), r.rule(), r.location(), r.value(), r.url()));
        }
        store.setString(K_FINDINGS, out.toString());
    }

    static List<ReconModel.FindingRow> loadFindings(PersistedObject store) {
        List<ReconModel.FindingRow> out = new ArrayList<>();
        String value = store.getString(K_FINDINGS);
        if (value == null || value.isBlank()) return out;
        for (String line : value.split("\n")) {
            String[] p = line.split("\t", -1);
            if (p.length == 6) out.add(new ReconModel.FindingRow(p[0], p[1], p[2], p[3], p[4], p[5]));
        }
        return out;
    }

    static void saveAssets(PersistedObject store, List<ReconModel.AssetRow> rows) {
        StringBuilder out = new StringBuilder();
        for (ReconModel.AssetRow r : rows) {
            if (out.length() > 0) out.append('\n');
            out.append(join(r.type(), r.value(), r.source()));
        }
        store.setString(K_ASSETS, out.toString());
    }

    static List<ReconModel.AssetRow> loadAssets(PersistedObject store) {
        List<ReconModel.AssetRow> out = new ArrayList<>();
        String value = store.getString(K_ASSETS);
        if (value == null || value.isBlank()) return out;
        for (String line : value.split("\n")) {
            String[] p = line.split("\t", -1);
            if (p.length == 3) out.add(new ReconModel.AssetRow(p[0], p[1], p[2]));
        }
        return out;
    }

    private static String join(String... fields) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < fields.length; i++) {
            if (i > 0) out.append('\t');
            out.append(sanitize(fields[i]));
        }
        return out.toString();
    }

    private static String sanitize(String value) {
        return value == null ? "" : value.replace('\t', ' ').replace('\n', ' ').replace('\r', ' ');
    }
}
