package com.victor.reconloop.contracts;

import org.junit.Test;

import java.util.List;
import java.util.UUID;

import static org.junit.Assert.*;

public class ContractValidatorTest {

    private final ContractValidator v = new ContractValidator();
    private final Scope scope = Scope.of("example", List.of("example.com", "*.example.com"));

    @Test
    public void acceptsInScopeApexAndSubdomain() {
        assertTrue(v.domain("example.com", scope, "manual").accepted());
        assertTrue(v.hostname("api.example.com", scope, "subfinder").accepted());
    }

    @Test
    public void rejectsOutOfScopeAndGarbageHosts() {
        assertFalse(v.hostname("evil.com", scope, "subfinder").accepted());
        assertEquals("out of scope", v.hostname("evil.com", scope, "subfinder").rejected().reason());
        assertFalse(v.hostname("not a host", scope, "amass").accepted());
        assertFalse(v.hostname("user@example.com", scope, "amass").accepted());
        assertFalse(v.hostname("https://example.com/path", scope, "amass").accepted());
        assertFalse(v.hostname("*.example.com", scope, "amass").accepted());
    }

    @Test
    public void rejectsPermutationPastGenerationCap() {
        ContractResult<Asset.Hostname> r = v.hostname("dev-api.example.com", scope, "dnsgen", 3);
        assertFalse(r.accepted());
        assertTrue(r.rejected().reason().contains("generation"));
    }

    @Test
    public void resolvedHostRequiresRecords() {
        assertFalse(v.resolvedHost("api.example.com", List.of(), List.of(), List.of(), scope, "dnsx", 0).accepted());
        assertTrue(v.resolvedHost("api.example.com", List.of("1.1.1.1"), List.of(), List.of(), scope, "dnsx", 0).accepted());
        assertTrue(v.resolvedHost("www.example.com", List.of(), List.of(), List.of("example.com"), scope, "dnsx", 0).accepted());
    }

    @Test
    public void publicIpIsScanEligibleRestrictedIsNot() {
        ContractResult<Asset.IpOrCidr> pub = v.ipOrCidr("8.8.8.8", true, "dnsx");
        assertTrue(pub.accepted());
        assertTrue(pub.value().scanEligible());
        assertFalse(pub.value().restricted());

        ContractResult<Asset.IpOrCidr> priv = v.ipOrCidr("10.0.0.5", true, "dnsx");
        assertTrue(priv.accepted());
        assertTrue(priv.value().restricted());
        assertFalse(priv.value().scanEligible());
        assertEquals("rfc1918", priv.value().restriction());

        ContractResult<Asset.IpOrCidr> meta = v.ipOrCidr("169.254.169.254", true, "dnsx");
        assertTrue(meta.accepted());
        assertFalse(meta.value().scanEligible());
    }

    @Test
    public void wideCidrIsInventoryOnly() {
        ContractResult<Asset.IpOrCidr> wide = v.ipOrCidr("8.8.8.0/16", true, "whois");
        assertTrue(wide.accepted());
        assertTrue(wide.value().cidr());
        assertFalse(wide.value().scanEligible());

        ContractResult<Asset.IpOrCidr> tight = v.ipOrCidr("8.8.8.0/24", true, "whois");
        assertTrue(tight.accepted());
        assertTrue(tight.value().scanEligible());
    }

    @Test
    public void serviceRejectsBadPortsAndProtocols() {
        assertTrue(v.service("1.1.1.1", 443, "TCP", "naabu").accepted());
        assertFalse(v.service("1.1.1.1", 0, "tcp", "naabu").accepted());
        assertFalse(v.service("1.1.1.1", 80, "sctp", "naabu").accepted());
        assertFalse(v.service("1.1.1.0/24", 80, "tcp", "naabu").accepted());
    }

    @Test
    public void httpAndUrlNormalizeAndScopeCheck() {
        ContractResult<Asset.HttpTarget> http = v.httpTarget(
                "HTTPS://API.EXAMPLE.COM:443/v1?b=2&a=1#frag", 200, "ok", "nginx", scope, "httpx");
        assertTrue(http.accepted());
        assertEquals("api.example.com", http.value().host());
        assertEquals(443, http.value().port());
        assertEquals("https://api.example.com/v1?a=1&b=2", http.value().url().toString());

        assertFalse(v.httpTarget("https://evil.com/", 200, "", "", scope, "httpx").accepted());
        assertFalse(v.url("javascript:alert(1)", scope, "katana").accepted());
        assertFalse(v.httpTarget("https://api.example.com/", 99, "", "", scope, "httpx").accepted());
    }

    @Test
    public void parameterizedUrlRequiresName() {
        assertFalse(v.parameterizedUrl("https://api.example.com/x", "  ", ParamLocation.QUERY,
                PayloadFamily.XSS, scope, "arjun").accepted());
        assertTrue(v.parameterizedUrl("https://api.example.com/x?q=1", "q", ParamLocation.QUERY,
                PayloadFamily.XSS, scope, "arjun").accepted());
    }

    @Test
    public void findingRequiresEvidenceRunIdAndKnownSeverity() {
        UUID run = UUID.fromString("11111111-1111-1111-1111-111111111111");
        assertTrue(v.finding("nuclei", "https://api.example.com/", "HIGH", VerificationState.CANDIDATE,
                "template xyz matched", run, "nuclei-v3", "nuclei").accepted());
        assertFalse(v.finding("nuclei", "https://api.example.com/", "nope", VerificationState.CANDIDATE,
                "x", run, "v", "nuclei").accepted());
        assertFalse(v.finding("nuclei", "https://api.example.com/", "high", VerificationState.CANDIDATE,
                "", run, "v", "nuclei").accepted());
        assertFalse(v.finding("nuclei", "https://api.example.com/", "high", VerificationState.CANDIDATE,
                "x", null, "v", "nuclei").accepted());
    }

    @Test
    public void quarantineAbsorbsRejects() {
        Quarantine q = new Quarantine();
        q.absorb(v.hostname("evil.com", scope, "subfinder"));
        q.absorb(v.hostname("api.example.com", scope, "subfinder"));
        assertEquals(1, q.size());
        assertEquals("hostname[]", q.snapshot().get(0).schema());
    }
}
