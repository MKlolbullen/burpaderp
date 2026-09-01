package com.victor.reconloop.contracts;

import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;

/**
 * Program scope used by every contract validator.
 *
 * <p>Include rules:
 * <ul>
 *   <li>{@code example.com} - that host and any subdomain</li>
 *   <li>{@code *.example.com} - subdomains only, not the apex</li>
 *   <li>{@code .example.com} - same as the apex-plus-children form</li>
 * </ul>
 * Exclude rules win. Empty include means "no host is in scope" (fail closed).
 */
public record Scope(String program, Set<String> include, Set<String> exclude, boolean allowWildcards) {

    public Scope {
        program = program == null ? "" : program.strip();
        include = freeze(include);
        exclude = freeze(exclude);
    }

    public static Scope of(String program, Collection<String> include) {
        return new Scope(program, setOf(include), Set.of(), true);
    }

    public static Scope of(String program, Collection<String> include, Collection<String> exclude) {
        return new Scope(program, setOf(include), setOf(exclude), true);
    }

    public boolean isEmpty() {
        return include.isEmpty();
    }

    public boolean allowsHost(String host) {
        String h = HostNames.canonical(host);
        if (h.isEmpty()) return false;
        if (matchesAny(h, exclude)) return false;
        return matchesAny(h, include);
    }

    public boolean allowsWildcardPattern(String raw) {
        if (!allowWildcards) return false;
        String p = HostNames.canonical(raw.startsWith("*.") ? raw.substring(2) : raw);
        return !p.isEmpty() && allowsHost(p);
    }

    private static boolean matchesAny(String host, Set<String> rules) {
        for (String rule : rules) {
            if (matches(host, rule)) return true;
        }
        return false;
    }

    static boolean matches(String host, String rule) {
        String r = HostNames.canonical(rule);
        if (r.isEmpty()) return false;
        boolean childrenOnly = false;
        if (r.startsWith("*.")) {
            childrenOnly = true;
            r = r.substring(2);
        } else if (r.startsWith(".")) {
            childrenOnly = true;
            r = r.substring(1);
        }
        if (r.isEmpty()) return false;
        if (host.equals(r)) return !childrenOnly;
        return host.endsWith("." + r);
    }

    private static Set<String> setOf(Collection<String> in) {
        if (in == null) return Set.of();
        LinkedHashSet<String> out = new LinkedHashSet<>();
        for (String s : in) {
            String c = HostNames.canonical(s);
            if (!c.isEmpty()) out.add(c);
        }
        return Set.copyOf(out);
    }

    private static Set<String> freeze(Set<String> in) {
        if (in == null || in.isEmpty()) return Set.of();
        LinkedHashSet<String> out = new LinkedHashSet<>();
        for (String s : in) {
            if (s != null && !s.isBlank()) out.add(s.strip().toLowerCase(Locale.ROOT));
        }
        return Set.copyOf(out);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Scope other)) return false;
        return allowWildcards == other.allowWildcards
                && Objects.equals(program, other.program)
                && include.equals(other.include)
                && exclude.equals(other.exclude);
    }

    @Override
    public int hashCode() {
        return Objects.hash(program, include, exclude, allowWildcards);
    }
}
