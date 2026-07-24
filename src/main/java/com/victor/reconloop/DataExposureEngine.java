package com.victor.reconloop;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Passive JSON-field-name heuristics for two categories no existing engine covers: excessive data
 * exposure (a response returning fields a client shouldn't see) and mass assignment (a request
 * setting fields a client shouldn't control). Both walk parsed JSON looking for KEY NAMES on a
 * curated list — this is about the shape of the data, not a specific secret/value pattern (that's
 * RegexHound's job), so it complements rather than duplicates it. Pure and dependency-free (reuses
 * the existing {@link Json} parser), so it works identically from live traffic or the CLI scanner.
 */
final class DataExposureEngine {

    record Field(String path, String key, String valuePreview) {}

    private static final Set<String> SENSITIVE_RESPONSE_FIELDS = Set.of(
            "password", "passwordhash", "hashedpassword", "salt", "passwordsalt",
            "ssn", "socialsecuritynumber", "nationalid", "taxid",
            "creditcard", "cardnumber", "cvv", "cvv2",
            "bankaccount", "routingnumber", "iban", "swift",
            "apikey", "privatekey", "secretkey", "accesstoken", "refreshtoken", "clientsecret",
            "securityanswer", "securityquestion",
            "internalnotes", "adminnotes", "internalonly",
            "dateofbirth", "dob");

    private static final Set<String> PRIVILEGED_REQUEST_FIELDS = Set.of(
            "role", "roles", "isadmin", "admin", "superuser", "issuperuser",
            "permissions", "scope", "scopes", "accountlevel", "accounttype", "usertype",
            "verified", "isverified", "emailverified",
            "balance", "credits", "price", "discount", "plan", "subscriptiontier",
            "approved", "locked", "islocked", "banned", "isbanned",
            "ownerid");

    private static final int MAX_DEPTH = 12;
    private static final int MAX_FIELDS = 40;
    private static final int MAX_ARRAY_ELEMENTS = 50;

    static List<Field> excessiveDataExposure(String body) {
        return scan(body, SENSITIVE_RESPONSE_FIELDS);
    }

    static List<Field> massAssignmentCandidates(String body) {
        return scan(body, PRIVILEGED_REQUEST_FIELDS);
    }

    private static List<Field> scan(String body, Set<String> targetKeys) {
        Object root = tryParse(body);
        if (root == null) return List.of();
        List<Field> out = new ArrayList<>();
        walk(root, "$", targetKeys, out, 0);
        return out;
    }

    private static Object tryParse(String body) {
        if (body == null || body.isBlank()) return null;
        String trimmed = body.strip();
        if (!trimmed.startsWith("{") && !trimmed.startsWith("[")) return null;
        try {
            return Json.parse(trimmed);
        } catch (Exception e) {
            return null;
        }
    }

    private static void walk(Object node, String path, Set<String> targetKeys, List<Field> out, int depth) {
        if (out.size() >= MAX_FIELDS || depth > MAX_DEPTH) return;
        if (node instanceof Map<?, ?> map) {
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                if (out.size() >= MAX_FIELDS) return;
                String key = String.valueOf(entry.getKey());
                Object value = entry.getValue();
                String childPath = path + "." + key;
                if (targetKeys.contains(normalize(key))) {
                    out.add(new Field(childPath, key, preview(value)));
                }
                walk(value, childPath, targetKeys, out, depth + 1);
            }
        } else if (node instanceof List<?> list) {
            for (int i = 0; i < list.size() && i < MAX_ARRAY_ELEMENTS; i++) {
                if (out.size() >= MAX_FIELDS) return;
                walk(list.get(i), path + "[" + i + "]", targetKeys, out, depth + 1);
            }
        }
    }

    private static String normalize(String key) {
        return key.toLowerCase(Locale.ROOT).replace("_", "").replace("-", "");
    }

    private static String preview(Object value) {
        if (value == null) return "null";
        String s = String.valueOf(value);
        return s.length() > 60 ? s.substring(0, 57) + "..." : s;
    }
}
