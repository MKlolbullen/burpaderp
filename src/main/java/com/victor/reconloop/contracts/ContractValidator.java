package com.victor.reconloop.contracts;

import java.net.URI;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;

/**
 * Fail-closed parsers for every node on the recon DAG.
 * Callers pass raw tool output; accepted values are normalized contracts,
 * everything else becomes {@link Rejected}.
 */
public final class ContractValidator {
    public static final int DEFAULT_MAX_GENERATION = 2;
    public static final int DEFAULT_MIN_SCAN_PREFIX_V4 = 24;
    public static final int DEFAULT_MIN_SCAN_PREFIX_V6 = 120;

    private static final Set<String> SEVERITIES = Set.of("info", "information", "low", "medium", "high", "critical");

    private final int maxGeneration;
    private final int minScanPrefixV4;
    private final int minScanPrefixV6;

    public ContractValidator() {
        this(DEFAULT_MAX_GENERATION, DEFAULT_MIN_SCAN_PREFIX_V4, DEFAULT_MIN_SCAN_PREFIX_V6);
    }

    public ContractValidator(int maxGeneration, int minScanPrefixV4, int minScanPrefixV6) {
        this.maxGeneration = Math.max(0, maxGeneration);
        this.minScanPrefixV4 = minScanPrefixV4;
        this.minScanPrefixV6 = minScanPrefixV6;
    }

    public ContractResult<Asset.Domain> domain(String raw, Scope scope, String source) {
        String err = HostNames.validateFqdn(raw, false);
        if (err != null) return reject("domain[]", err, raw, source);
        Asset.Domain d = new Asset.Domain(raw, scope, source);
        if (scope == null || scope.isEmpty() || !scope.allowsHost(d.fqdn())) {
            return reject("domain[]", "out of scope", raw, source);
        }
        return ContractResult.ok(d);
    }

    public ContractResult<Asset.Hostname> hostname(String raw, Scope scope, String source) {
        return hostname(raw, scope, source, 0);
    }

    public ContractResult<Asset.Hostname> hostname(String raw, boolean inScope, String source, int generation) {
        if (generation > maxGeneration) {
            return reject("hostname[]", "permutation generation " + generation + " exceeds cap " + maxGeneration, raw, source);
        }
        if (raw != null && raw.strip().startsWith("*.")) {
            return reject("hostname[]", "wildcard names belong on domain[], not hostname[]", raw, source);
        }
        String formatError = HostNames.validateFqdn(raw, false);
        if (formatError != null) return reject("hostname[]", formatError, raw, source);
        if (!inScope) return reject("hostname[]", "out of scope", raw, source);
        return ContractResult.ok(new Asset.Hostname(raw, Scope.of("burp", List.of(HostNames.canonical(raw))), source, generation));
    }

    public ContractResult<Asset.Hostname> hostname(String raw, Scope scope, String source, int generation) {
        if (generation > maxGeneration) {
            return reject("hostname[]", "permutation generation " + generation + " exceeds cap " + maxGeneration, raw, source);
        }
        boolean wildcard = raw != null && raw.strip().startsWith("*.");
        if (wildcard) {
            if (scope == null || !scope.allowsWildcardPattern(raw)) {
                return reject("hostname[]", "wildcard out of scope or wildcards disabled", raw, source);
            }
            return reject("hostname[]", "wildcard names belong on domain[], not hostname[]", raw, source);
        }
        String err = HostNames.validateFqdn(raw, false);
        if (err != null) return reject("hostname[]", err, raw, source);
        Asset.Hostname h = new Asset.Hostname(raw, scope, source, generation);
        if (scope == null || scope.isEmpty() || !scope.allowsHost(h.fqdn())) {
            return reject("hostname[]", "out of scope", raw, source);
        }
        return ContractResult.ok(h);
    }

    public ContractResult<Asset.ResolvedHost> resolvedHost(
            String hostname, List<String> a, List<String> aaaa, List<String> cname,
            Scope scope, String source, int generation) {
        ContractResult<Asset.Hostname> host = hostname(hostname, scope, source, generation);
        if (!host.accepted()) {
            return ContractResult.reject("resolved_host[]", host.rejected().reason(), hostname, source);
        }
        Asset.ResolvedHost resolved = new Asset.ResolvedHost(hostname, a, aaaa, cname, source, generation);
        if (!resolved.hasAddress() && resolved.cname().isEmpty()) {
            return reject("resolved_host[]", "no A/AAAA/CNAME records", hostname, source);
        }
        return ContractResult.ok(resolved);
    }

    public ContractResult<Asset.IpOrCidr> ipOrCidr(String raw, boolean inScope, String source) {
        NetAddresses.Parsed parsed = NetAddresses.parse(raw);
        if (!parsed.ok()) return reject("ip|cidr", parsed.error(), raw, source);
        boolean restricted = parsed.restriction() != null;
        boolean scanEligible = NetAddresses.scanEligible(parsed, minScanPrefixV4, minScanPrefixV6);
        Asset.IpOrCidr asset = new Asset.IpOrCidr(
                parsed.canonical(), parsed.cidr(), parsed.prefixLength(),
                inScope, scanEligible && inScope && !restricted,
                restricted, restricted ? parsed.restriction() : "", source);
        if (!inScope) return reject("ip|cidr", "out of scope", raw, source);
        return ContractResult.ok(asset);
    }

    public ContractResult<Asset.IpOrCidr> ipOrCidr(String raw, Scope scope, String source) {
        NetAddresses.Parsed parsed = NetAddresses.parse(raw);
        if (!parsed.ok()) return reject("ip|cidr", parsed.error(), raw, source);
        boolean inScope = scope != null && !scope.isEmpty() && scopeAllowsIp(scope, parsed);
        return ipOrCidr(raw, inScope, source);
    }

    public ContractResult<Asset.Service> service(String ip, int port, String protocol, String source) {
        NetAddresses.Parsed parsed = NetAddresses.parse(ip);
        if (!parsed.ok() || parsed.cidr()) return reject("service[]", "service requires a single IP", ip, source);
        if (port < 1 || port > 65535) return reject("service[]", "port out of range", ip + ":" + port, source);
        String proto = protocol == null ? "tcp" : protocol.strip().toLowerCase(Locale.ROOT);
        if (!proto.equals("tcp") && !proto.equals("udp")) {
            return reject("service[]", "protocol must be tcp or udp", proto, source);
        }
        return ContractResult.ok(new Asset.Service(parsed.canonical(), port, proto, source));
    }

    public ContractResult<Asset.HttpTarget> httpTarget(String rawUrl, int status, String title, String tech,
                                                       Scope scope, String source) {
        String err = Urls.rejectReason(rawUrl);
        if (err != null) return reject("http_target[]", err, rawUrl, source);
        URI url = Urls.normalize(rawUrl);
        String host = HostNames.canonical(url.getHost());
        if (scope == null || scope.isEmpty() || !scope.allowsHost(host)) {
            return reject("http_target[]", "out of scope", rawUrl, source);
        }
        if (status < 100 || status > 599) {
            return reject("http_target[]", "invalid HTTP status " + status, rawUrl, source);
        }
        return ContractResult.ok(new Asset.HttpTarget(
                url, host, Urls.effectivePort(url), status, title == null ? "" : title,
                tech == null ? "" : tech, source));
    }

    public ContractResult<Asset.Url> url(String rawUrl, boolean inScope, String source) {
        String err = Urls.rejectReason(rawUrl);
        if (err != null) return reject("url[]", err, rawUrl, source);
        if (!inScope) return reject("url[]", "out of scope", rawUrl, source);
        java.net.URI url = Urls.normalize(rawUrl);
        return ContractResult.ok(new Asset.Url(url, Urls.normalizeQuery(url.getRawQuery()), true, source));
    }

    public ContractResult<Asset.Url> url(String rawUrl, Scope scope, String source) {
        String err = Urls.rejectReason(rawUrl);
        if (err != null) return reject("url[]", err, rawUrl, source);
        URI url = Urls.normalize(rawUrl);
        boolean inScope = scope != null && !scope.isEmpty() && scope.allowsHost(url.getHost());
        if (!inScope) return reject("url[]", "out of scope", rawUrl, source);
        return ContractResult.ok(new Asset.Url(url, Urls.normalizeQuery(url.getRawQuery()), true, source));
    }

    public ContractResult<Asset.ParameterizedUrl> parameterizedUrl(
            String rawUrl, String name, ParamLocation location, PayloadFamily hint,
            Scope scope, String source) {
        ContractResult<Asset.Url> base = url(rawUrl, scope, source);
        if (!base.accepted()) {
            return ContractResult.reject("parameterized_url[]", base.rejected().reason(), rawUrl, source);
        }
        if (name == null || name.isBlank()) {
            return reject("parameterized_url[]", "empty parameter name", rawUrl, source);
        }
        return ContractResult.ok(new Asset.ParameterizedUrl(
                base.value().url(), name.strip(), location, hint, source));
    }

    public ContractResult<Asset.Finding> finding(
            String tool, String rawTarget, String severity, VerificationState state,
            String evidence, UUID runId, String detectorVersion, String source) {
        if (tool == null || tool.isBlank()) return reject("finding[]", "missing tool", rawTarget, source);
        String err = Urls.rejectReason(rawTarget);
        if (err != null) return reject("finding[]", "finding target " + err, rawTarget, source);
        if (severity == null || !SEVERITIES.contains(severity.strip().toLowerCase(Locale.ROOT))) {
            return reject("finding[]", "unknown severity", severity, source);
        }
        if (evidence == null || evidence.isBlank()) {
            return reject("finding[]", "missing evidence", rawTarget, source);
        }
        if (runId == null) return reject("finding[]", "missing run id", rawTarget, source);
        URI target = Urls.normalize(rawTarget);
        String sev = severity.strip().toLowerCase(Locale.ROOT);
        if (sev.equals("information")) sev = "info";
        return ContractResult.ok(new Asset.Finding(
                tool.strip(), target, sev, state, evidence.strip(), runId, detectorVersion, source));
    }

    public int maxGeneration() {
        return maxGeneration;
    }

    private static boolean scopeAllowsIp(Scope scope, NetAddresses.Parsed parsed) {
        return scope.include().contains(parsed.canonical())
                || scope.include().contains(parsed.addr().getHostAddress());
    }

    private static <T> ContractResult<T> reject(String schema, String reason, String raw, String source) {
        return ContractResult.reject(schema, reason, raw == null ? "" : raw, source == null ? "" : source);
    }
}
