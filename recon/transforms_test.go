package recon

import "testing"

func TestResolvedHostToIPsMarksNetworkTargetsDerived(t *testing.T) {
	record := Record{
		Kind: KindResolvedHost, Hostname: "api.example.com",
		Addresses: []string{"203.0.113.10", "2001:db8::10"}, Source: "dnsx", RunID: "run-1",
	}
	ips, err := ResolvedHostToIPs(record)
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 2 {
		t.Fatalf("got %d IPs", len(ips))
	}
	for _, ip := range ips {
		if !ip.Derived || ip.Hostname != "api.example.com" || ip.RunID != "run-1" {
			t.Fatalf("lost provenance in %#v", ip)
		}
	}
}

func TestResolvedHostToHostnamePreservesSNIIdentity(t *testing.T) {
	host, err := ResolvedHostToHostname(Record{Kind: KindResolvedHost, Hostname: "api.example.com", Addresses: []string{"203.0.113.10"}})
	if err != nil {
		t.Fatal(err)
	}
	if host.Kind != KindHostname || host.Value != "api.example.com" {
		t.Fatalf("unexpected %#v", host)
	}
}

func TestDedupeRecordsKeepsParameterizedURLNamesSeparate(t *testing.T) {
	in := []Record{
		{Kind: KindParameterizedURL, URL: "https://api.example.com/?a=1", Parameter: "a"},
		{Kind: KindParameterizedURL, URL: "https://api.example.com/?a=1", Parameter: "a"},
		{Kind: KindParameterizedURL, URL: "https://api.example.com/?a=1", Parameter: "b"},
	}
	out := DedupeRecords(in)
	if len(out) != 2 {
		t.Fatalf("got %d records", len(out))
	}
}
