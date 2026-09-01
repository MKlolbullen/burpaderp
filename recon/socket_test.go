package recon

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestSocketRejectsWrongInputKind(t *testing.T) {
	scope, _ := NewScope([]string{"example.com"}, nil, false)
	dnsx, _ := DefaultToolRegistry().MustGet("dnsx")
	socket := NewContractSocket(scope, dnsx)
	if _, err := socket.Validate(DirectionInput, Record{Kind: KindURL, URL: "https://api.example.com/"}); err == nil {
		t.Fatal("dnsx must not accept URL records")
	}
	if _, err := socket.Validate(DirectionInput, Record{Kind: KindHostname, Hostname: "api.example.com"}); err != nil {
		t.Fatalf("valid hostname rejected: %v", err)
	}
}

func TestSocketQuarantinesMalformedAndOutOfScopeOutput(t *testing.T) {
	scope, _ := NewScope([]string{"example.com"}, nil, false)
	dnsx, _ := DefaultToolRegistry().MustGet("dnsx")
	socket := NewContractSocket(scope, dnsx)
	input := strings.Join([]string{
		`{"kind":"resolved_host","hostname":"api.example.com","addresses":["203.0.113.10"]}`,
		`not-json`,
		`{"kind":"resolved_host","hostname":"api.evil.test","addresses":["198.51.100.3"]}`,
	}, "\n") + "\n"
	var accepted bytes.Buffer
	var rejected bytes.Buffer
	stats, err := socket.FilterJSONL(DirectionOutput, "dnsx-test", strings.NewReader(input), &accepted, &rejected)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Accepted != 1 || stats.Rejected != 2 {
		t.Fatalf("unexpected stats %#v", stats)
	}
	var good Record
	if err := json.Unmarshal(bytes.TrimSpace(accepted.Bytes()), &good); err != nil {
		t.Fatalf("accepted output is not JSON: %v", err)
	}
	if good.Hostname != "api.example.com" {
		t.Fatalf("unexpected accepted record %#v", good)
	}
	if !strings.Contains(rejected.String(), "invalid JSON") || !strings.Contains(rejected.String(), "outside scope") {
		t.Fatalf("quarantine lost reasons: %s", rejected.String())
	}
}

func TestNaabuInputRejectsDNSDerivedIPByDefault(t *testing.T) {
	scope, _ := NewScope([]string{"example.com"}, nil, false)
	naabu, _ := DefaultToolRegistry().MustGet("naabu")
	socket := NewContractSocket(scope, naabu)
	_, err := socket.Validate(DirectionInput, Record{
		Kind: KindIP, IP: "203.0.113.10", Hostname: "api.example.com", Derived: true,
	})
	if err == nil {
		t.Fatal("derived DNS IP escaped the explicit network-scope gate")
	}
}
