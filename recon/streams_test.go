package recon

import (
	"bytes"
	"strings"
	"testing"
)

func TestRenderJSONLInputsDropsIncompatibleRecords(t *testing.T) {
	scope, _ := NewScope([]string{"example.com"}, nil, false)
	dnsx, _ := DefaultToolRegistry().MustGet("dnsx")
	socket := NewContractSocket(scope, dnsx)
	input := strings.Join([]string{
		`{"kind":"hostname","hostname":"api.example.com"}`,
		`{"kind":"url","url":"https://api.example.com/"}`,
	}, "\n") + "\n"
	var toolIn, rejected bytes.Buffer
	stats, err := RenderJSONLInputs(socket, "test", strings.NewReader(input), &toolIn, &rejected)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Accepted != 1 || stats.Rejected != 1 {
		t.Fatalf("unexpected stats %#v", stats)
	}
	if toolIn.String() != "api.example.com\n" {
		t.Fatalf("unexpected tool stdin %q", toolIn.String())
	}
	if !strings.Contains(rejected.String(), "cannot consume url") {
		t.Fatalf("missing quarantine reason: %s", rejected.String())
	}
}

func TestAdaptToolOutputParsesThenScopeChecks(t *testing.T) {
	scope, _ := NewScope([]string{"example.com"}, nil, false)
	dnsx, _ := DefaultToolRegistry().MustGet("dnsx")
	socket := NewContractSocket(scope, dnsx)
	raw := strings.Join([]string{
		`{"host":"api.example.com","a":["203.0.113.10"]}`,
		`{"host":"api.evil.test","a":["198.51.100.2"]}`,
	}, "\n") + "\n"
	var normalized, rejected bytes.Buffer
	stats, err := AdaptToolOutput(socket, "dnsx", strings.NewReader(raw), &normalized, &rejected)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Accepted != 1 || stats.Rejected != 1 {
		t.Fatalf("unexpected stats %#v", stats)
	}
	if !strings.Contains(normalized.String(), `"kind":"resolved_host"`) {
		t.Fatalf("missing normalized record: %s", normalized.String())
	}
	if !strings.Contains(rejected.String(), "outside scope") {
		t.Fatalf("missing scope rejection: %s", rejected.String())
	}
}
