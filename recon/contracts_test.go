package recon

import (
	"strings"
	"testing"
)

func TestNormalizeFQDN(t *testing.T) {
	got, err := NormalizeFQDN("API.Example.COM.")
	if err != nil {
		t.Fatal(err)
	}
	if got != "api.example.com" {
		t.Fatalf("got %q", got)
	}
	for _, bad := range []string{"localhost", "-bad.example.com", "bad_.example.com", ""} {
		if _, err := NormalizeFQDN(bad); err == nil {
			t.Fatalf("expected %q to fail", bad)
		}
	}
}

func TestDomainScopeIncludesOnlyRootAndSubdomains(t *testing.T) {
	scope, err := NewScope([]string{"example.com"}, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if !scope.InScopeHostname("a.b.example.com") {
		t.Fatal("expected subdomain in scope")
	}
	if scope.InScopeHostname("example.com.evil.test") {
		t.Fatal("suffix-confusion hostname escaped scope")
	}
}

func TestDerivedIPRequiresExplicitOptIn(t *testing.T) {
	strict, err := NewScope([]string{"example.com"}, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	record := Record{Kind: KindIP, IP: "203.0.113.10", Hostname: "api.example.com", Derived: true}
	if _, err := strict.Validate(record); err == nil || !strings.Contains(err.Error(), "derived IP probing is disabled") {
		t.Fatalf("expected derived IP rejection, got %v", err)
	}

	permissive, err := NewScope([]string{"example.com"}, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	got, err := permissive.Validate(record)
	if err != nil {
		t.Fatalf("allow-derived-ips should accept DNS-derived IP: %v", err)
	}
	if got.IP != "203.0.113.10" {
		t.Fatalf("unexpected canonical IP %q", got.IP)
	}
}

func TestExplicitCIDRAllowsNetworkService(t *testing.T) {
	scope, err := NewScope(nil, []string{"203.0.113.0/24"}, false)
	if err != nil {
		t.Fatal(err)
	}
	got, err := scope.Validate(Record{Kind: KindService, IP: "203.0.113.8", Port: 443, Protocol: "TCP"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Value != "203.0.113.8:443/tcp" {
		t.Fatalf("unexpected service value %q", got.Value)
	}
	if _, err := scope.Validate(Record{Kind: KindService, IP: "198.51.100.8", Port: 443}); err == nil {
		t.Fatal("out-of-scope service should fail")
	}
}

func TestNormalizeHTTPURLCanonicalizesPortFragmentAndQuery(t *testing.T) {
	got, err := NormalizeHTTPURL("HTTPS://API.Example.COM:443/path?b=2&a=2&a=1#frag")
	if err != nil {
		t.Fatal(err)
	}
	want := "https://api.example.com/path?a=1&a=2&b=2"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestResolvedHostRequiresDNSMaterial(t *testing.T) {
	scope, _ := NewScope([]string{"example.com"}, nil, false)
	if _, err := scope.Validate(Record{Kind: KindResolvedHost, Hostname: "www.example.com"}); err == nil {
		t.Fatal("resolved_host without DNS material should fail")
	}
	got, err := scope.Validate(Record{
		Kind: KindResolvedHost, Hostname: "www.example.com",
		Addresses: []string{"2001:db8::1", "203.0.113.5", "203.0.113.5"},
		CNAMEs: []string{"shared.cdn.example.net."},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Addresses) != 2 || got.CNAMEs[0] != "shared.cdn.example.net" {
		t.Fatalf("unexpected normalized DNS record: %#v", got)
	}
}

func TestParameterizedURLContract(t *testing.T) {
	scope, _ := NewScope([]string{"example.com"}, nil, false)
	got, err := scope.Validate(Record{Kind: KindParameterizedURL, URL: "https://api.example.com/users?id=1", Parameter: "id"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Parameter != "id" || got.URL == "" {
		t.Fatalf("unexpected record %#v", got)
	}
	if _, err := scope.Validate(Record{Kind: KindParameterizedURL, URL: "https://api.example.com/users", Parameter: "bad\nname"}); err == nil {
		t.Fatal("control characters in parameter name should fail")
	}
}
