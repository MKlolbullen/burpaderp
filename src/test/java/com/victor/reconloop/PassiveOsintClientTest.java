package com.victor.reconloop;

import org.junit.Test;

import java.net.URI;
import java.net.http.HttpRequest;
import java.util.List;

import static org.junit.Assert.*;

public class PassiveOsintClientTest {

    @Test
    public void shodanDnsKeepsInZoneNamesAndAddresses() {
        String json = """
                {"domain":"example.com","more":true,"subdomains":["www","mail"],"data":[
                  {"subdomain":"www","type":"A","value":"93.184.216.34"},
                  {"subdomain":"mail","type":"AAAA","value":"2606:2800:220:1:248:1893:25c8:1946"},
                  {"subdomain":"www","type":"CNAME","value":"cdn.example.net"},
                  {"subdomain":"ns","type":"CNAME","value":"ns.example.com"},
                  {"subdomain":"www","type":"TXT","value":"password = hunter2"}
                ]}
                """;

        PassiveOsintClient.LookupResult result = PassiveOsintClient.parse(
                PassiveOsintClient.Provider.SHODAN, json, "example.com");

        assertTrue(values(result, "host").contains("www.example.com"));
        assertTrue(values(result, "host").contains("mail.example.com"));
        assertTrue(values(result, "host").contains("ns.example.com"));
        assertFalse(values(result, "host").contains("cdn.example.net"));
        assertTrue(values(result, "ipv4").contains("93.184.216.34"));
        assertTrue(values(result, "ipv6").contains("2606:2800:220:1:248:1893:25c8:1946"));
        assertTrue(result.observations().stream().noneMatch(o -> o.value().contains("hunter2")));
        assertEquals(List.of("Shodan has more DNS records than the first page."), result.notes());
    }

    @Test
    public void censysPairsAddressesOnlyWithInZoneHits() {
        String json = """
                {"result":{"hits":[
                  {"ip":"93.184.216.34","dns":{"names":["www.example.com","other.net"]},"banner":"password = hunter2"},
                  {"ip":"198.51.100.9","dns":{"names":["other.net"]}}
                ]}}
                """;

        PassiveOsintClient.LookupResult result = PassiveOsintClient.parse(
                PassiveOsintClient.Provider.CENSYS, json, "https://example.com/path");

        assertEquals(List.of("www.example.com"), values(result, "host"));
        assertEquals(List.of("93.184.216.34"), values(result, "ipv4"));
        assertTrue(result.observations().stream().noneMatch(o -> o.value().contains("hunter2")));
    }

    @Test
    public void virusTotalSubdomainsAndResolutionsStayInZone() {
        String subdomains = """
                {"data":[{"id":"api.example.com","type":"domain"},{"id":"evil.example.net","type":"domain"}]}
                """;
        String resolutions = """
                {"data":[
                  {"attributes":{"ip_address":"93.184.216.34","host_name":"example.com"}},
                  {"attributes":{"ip_address":"198.51.100.9","host_name":"other.net"}}
                ]}
                """;

        PassiveOsintClient.LookupResult hosts = PassiveOsintClient.parse(
                PassiveOsintClient.Provider.VIRUSTOTAL, subdomains, "example.com");
        PassiveOsintClient.LookupResult addresses = PassiveOsintClient.parse(
                PassiveOsintClient.Provider.VIRUSTOTAL, resolutions, "example.com", true);

        assertEquals(List.of("api.example.com"), values(hosts, "host"));
        assertEquals(List.of("example.com"), values(addresses, "host"));
        assertEquals(List.of("93.184.216.34"), values(addresses, "ipv4"));
    }

    @Test
    public void fofaKeepsRowsWhoseHostIsInZone() {
        String json = """
                {"error":false,"results":[
                  ["https://www.example.com/app","93.184.216.34","443"],
                  ["api.example.com:8443","203.0.113.5","8443"],
                  ["evil.example.net","198.51.100.8","80"]
                ]}
                """;

        PassiveOsintClient.LookupResult result = PassiveOsintClient.parse(
                PassiveOsintClient.Provider.FOFA, json, "example.com");

        assertTrue(values(result, "host").contains("www.example.com"));
        assertTrue(values(result, "host").contains("api.example.com"));
        assertFalse(values(result, "host").contains("evil.example.net"));
        assertTrue(values(result, "ipv4").contains("93.184.216.34"));
        assertTrue(values(result, "ipv4").contains("203.0.113.5"));
        assertFalse(values(result, "ipv4").contains("198.51.100.8"));
    }

    @Test
    public void providerErrorObjectYieldsNoObservations() {
        PassiveOsintClient.LookupResult result = PassiveOsintClient.parse(
                PassiveOsintClient.Provider.FOFA, "{\"error\":true,\"errmsg\":\"invalid key\"}", "example.com");

        assertTrue(result.observations().isEmpty());
        assertEquals(List.of("FOFA reported an error."), result.notes());
    }

    @Test
    public void requestsGoToTheProviderAndNotTheTarget() {
        HttpRequest shodan = PassiveOsintClient.buildRequest(
                PassiveOsintClient.Provider.SHODAN, "example.com", "shodan-secret");
        HttpRequest censys = PassiveOsintClient.buildRequest(
                PassiveOsintClient.Provider.CENSYS, "example.com", "censys-secret");
        HttpRequest vt = PassiveOsintClient.buildRequest(
                PassiveOsintClient.Provider.VIRUSTOTAL, "example.com", "vt-secret");
        HttpRequest fofa = PassiveOsintClient.buildRequest(
                PassiveOsintClient.Provider.FOFA, "example.com", "fofa-secret");

        assertEquals("api.shodan.io", shodan.uri().getHost());
        assertTrue(shodan.uri().getRawQuery().contains("key=shodan-secret"));
        assertEquals("api.platform.censys.io", censys.uri().getHost());
        assertNull(censys.uri().getRawQuery());
        assertEquals("Bearer censys-secret", censys.headers().firstValue("Authorization").orElseThrow());
        assertEquals("www.virustotal.com", vt.uri().getHost());
        assertEquals("vt-secret", vt.headers().firstValue("x-apikey").orElseThrow());
        assertEquals("fofa.info", fofa.uri().getHost());
        for (HttpRequest request : List.of(shodan, censys, vt, fofa)) {
            URI uri = request.uri();
            assertNotEquals("example.com", uri.getHost());
            assertFalse(uri.getHost().endsWith(".example.com"));
        }
    }

    @Test
    public void missingKeyDoesNotCallTheNetwork() {
        PassiveOsintClient.LookupResult result = new PassiveOsintClient().lookup(
                PassiveOsintClient.Provider.SHODAN, "example.com", "  ");

        assertTrue(result.observations().isEmpty());
        assertEquals(List.of("Shodan skipped: set $SHODAN_API_KEY."), result.notes());
    }

    @Test
    public void invalidDomainIsRejectedBeforeARequest() {
        PassiveOsintClient.LookupResult result = new PassiveOsintClient().lookup(
                PassiveOsintClient.Provider.CENSYS, "not a domain", "token");

        assertTrue(result.observations().isEmpty());
        assertEquals(List.of("Invalid domain."), result.notes());
    }

    private static List<String> values(PassiveOsintClient.LookupResult result, String kind) {
        return result.observations().stream()
                .filter(o -> o.kind().equals(kind))
                .map(PassiveOsintClient.Observation::value)
                .toList();
    }
}
