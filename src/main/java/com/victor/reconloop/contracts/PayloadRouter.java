package com.victor.reconloop.contracts;

import java.util.ArrayList;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Maps a payload family onto parameterized URLs whose profiler hint is compatible.
 * RCE never routes unless {@link #allowDestructive} is set.
 */
public final class PayloadRouter {
    private static final Map<PayloadFamily, Set<PayloadFamily>> COMPAT = new EnumMap<>(PayloadFamily.class);

    static {
        COMPAT.put(PayloadFamily.XSS, EnumSet.of(PayloadFamily.XSS, PayloadFamily.GENERIC));
        COMPAT.put(PayloadFamily.SQLI, EnumSet.of(PayloadFamily.SQLI, PayloadFamily.GENERIC));
        COMPAT.put(PayloadFamily.SSTI, EnumSet.of(PayloadFamily.SSTI, PayloadFamily.XSS, PayloadFamily.GENERIC));
        COMPAT.put(PayloadFamily.LFI, EnumSet.of(PayloadFamily.LFI, PayloadFamily.GENERIC));
        COMPAT.put(PayloadFamily.SSRF, EnumSet.of(PayloadFamily.SSRF, PayloadFamily.OPEN_REDIRECT, PayloadFamily.GENERIC));
        COMPAT.put(PayloadFamily.OPEN_REDIRECT, EnumSet.of(PayloadFamily.OPEN_REDIRECT, PayloadFamily.SSRF, PayloadFamily.GENERIC));
        COMPAT.put(PayloadFamily.CRLF, EnumSet.of(PayloadFamily.CRLF, PayloadFamily.OPEN_REDIRECT, PayloadFamily.GENERIC));
        COMPAT.put(PayloadFamily.IDOR, EnumSet.of(PayloadFamily.IDOR, PayloadFamily.GENERIC));
        COMPAT.put(PayloadFamily.GRAPHQL, EnumSet.of(PayloadFamily.GRAPHQL, PayloadFamily.GENERIC));
        COMPAT.put(PayloadFamily.JWT, EnumSet.of(PayloadFamily.JWT, PayloadFamily.GENERIC));
        COMPAT.put(PayloadFamily.RCE, EnumSet.of(PayloadFamily.RCE));
        COMPAT.put(PayloadFamily.GENERIC, EnumSet.of(PayloadFamily.GENERIC));
    }

    private final boolean allowDestructive;

    public PayloadRouter() {
        this(false);
    }

    public PayloadRouter(boolean allowDestructive) {
        this.allowDestructive = allowDestructive;
    }

    public boolean compatible(PayloadFamily family, Asset.ParameterizedUrl target) {
        if (family == null || target == null) return false;
        if (family == PayloadFamily.RCE && !allowDestructive) return false;
        Set<PayloadFamily> accept = COMPAT.getOrDefault(family, Set.of());
        return accept.contains(target.familyHint());
    }

    public List<Asset.ParameterizedUrl> route(PayloadFamily family, Iterable<Asset.ParameterizedUrl> targets) {
        ArrayList<Asset.ParameterizedUrl> out = new ArrayList<>();
        if (targets == null) return out;
        for (Asset.ParameterizedUrl t : targets) {
            if (compatible(family, t)) out.add(t);
        }
        return List.copyOf(out);
    }

    /** Map ParameterProfiler class labels onto a family hint. */
    public static PayloadFamily hintFromProfilerClass(String attackClass) {
        if (attackClass == null) return PayloadFamily.GENERIC;
        String s = attackClass.toLowerCase(Locale.ROOT);
        if (s.contains("xss")) return PayloadFamily.XSS;
        if (s.contains("sqli")) return PayloadFamily.SQLI;
        if (s.contains("ssti")) return PayloadFamily.SSTI;
        if (s.contains("lfi") || s.contains("path")) return PayloadFamily.LFI;
        if (s.contains("rce") || s.contains("command")) return PayloadFamily.RCE;
        if (s.contains("ssrf")) return PayloadFamily.SSRF;
        if (s.contains("redirect")) return PayloadFamily.OPEN_REDIRECT;
        if (s.contains("idor") || s.contains("bola")) return PayloadFamily.IDOR;
        if (s.contains("graphql")) return PayloadFamily.GRAPHQL;
        if (s.contains("jwt")) return PayloadFamily.JWT;
        if (s.contains("crlf")) return PayloadFamily.CRLF;
        return PayloadFamily.GENERIC;
    }

    public static PayloadFamily fromManifestCategory(String category) {
        if (category == null) return PayloadFamily.GENERIC;
        String s = category.toLowerCase(Locale.ROOT);
        if (s.equals("xss")) return PayloadFamily.XSS;
        if (s.equals("sqli") || s.equals("sqli2")) return PayloadFamily.SQLI;
        if (s.equals("ssti")) return PayloadFamily.SSTI;
        if (s.equals("lfi")) return PayloadFamily.LFI;
        if (s.startsWith("rce")) return PayloadFamily.RCE;
        return PayloadFamily.GENERIC;
    }
}
