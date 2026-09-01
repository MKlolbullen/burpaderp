package com.victor.reconloop.contracts;

import java.net.URI;
import java.util.List;
import java.util.UUID;

public sealed interface Asset permits
        Asset.Domain, Asset.Hostname, Asset.ResolvedHost, Asset.IpOrCidr, Asset.Service,
        Asset.HttpTarget, Asset.Url, Asset.ParameterizedUrl, Asset.Finding {

    String source();

    record Domain(String fqdn, Scope scope, String source) implements Asset {
        public Domain {
            fqdn = HostNames.canonical(fqdn);
            source = nz(source);
        }
    }

    record Hostname(String fqdn, Scope scope, String source, int generation) implements Asset {
        public Hostname {
            fqdn = HostNames.canonical(fqdn);
            source = nz(source);
            if (generation < 0) generation = 0;
        }

        public Hostname(String fqdn, Scope scope, String source) {
            this(fqdn, scope, source, 0);
        }
    }

    record ResolvedHost(
            String hostname,
            List<String> a,
            List<String> aaaa,
            List<String> cname,
            String source,
            int generation
    ) implements Asset {
        public ResolvedHost {
            hostname = HostNames.canonical(hostname);
            a = copy(a);
            aaaa = copy(aaaa);
            cname = copy(cname);
            source = nz(source);
            if (generation < 0) generation = 0;
        }

        public boolean hasAddress() {
            return !a.isEmpty() || !aaaa.isEmpty();
        }
    }

    record IpOrCidr(
            String canonical,
            boolean cidr,
            int prefixLength,
            boolean inScope,
            boolean scanEligible,
            boolean restricted,
            String restriction,
            String source
    ) implements Asset {
        public IpOrCidr {
            canonical = nz(canonical);
            restriction = nz(restriction);
            source = nz(source);
        }
    }

    record Service(String ip, int port, String protocol, String source) implements Asset {
        public Service {
            ip = nz(ip);
            protocol = protocol == null || protocol.isBlank() ? "tcp" : protocol.toLowerCase();
            source = nz(source);
        }
    }

    record HttpTarget(
            URI url,
            String host,
            int port,
            int status,
            String title,
            String tech,
            String source
    ) implements Asset {
        public HttpTarget {
            host = HostNames.canonical(host);
            title = nz(title);
            tech = nz(tech);
            source = nz(source);
        }
    }

    record Url(URI url, String normalizedQuery, boolean inScope, String source) implements Asset {
        public Url {
            normalizedQuery = nz(normalizedQuery);
            source = nz(source);
        }
    }

    record ParameterizedUrl(
            URI url,
            String name,
            ParamLocation location,
            PayloadFamily familyHint,
            String source
    ) implements Asset {
        public ParameterizedUrl {
            name = nz(name);
            location = location == null ? ParamLocation.UNKNOWN : location;
            familyHint = familyHint == null ? PayloadFamily.GENERIC : familyHint;
            source = nz(source);
        }
    }

    record Finding(
            String tool,
            URI target,
            String severity,
            VerificationState state,
            String evidence,
            UUID runId,
            String detectorVersion,
            String source
    ) implements Asset {
        public Finding {
            tool = nz(tool);
            severity = severity == null ? "" : severity.toLowerCase();
            state = state == null ? VerificationState.SIGNAL : state;
            evidence = nz(evidence);
            detectorVersion = nz(detectorVersion);
            source = source == null || source.isBlank() ? tool : source;
        }
    }

    private static String nz(String s) {
        return s == null ? "" : s;
    }

    private static List<String> copy(List<String> in) {
        return in == null ? List.of() : List.copyOf(in);
    }
}
