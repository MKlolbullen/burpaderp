package recon

import (
	"strings"
	"testing"
)

func TestParseDNSXJSONL(t *testing.T) {
	records, err := ParseToolOutputLine("dnsx", `{"host":"api.example.com","a":["203.0.113.10"],"aaaa":["2001:db8::10"],"cname":["edge.example.net"]}`)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Kind != KindResolvedHost || len(records[0].Addresses) != 2 {
		t.Fatalf("unexpected %#v", records)
	}
}

func TestParseNaabuJSONL(t *testing.T) {
	records, err := ParseToolOutputLine("naabu", `{"ip":"203.0.113.10","port":443,"protocol":"tcp"}`)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Kind != KindService || records[0].Port != 443 {
		t.Fatalf("unexpected %#v", records)
	}
}

func TestParseHTTPXJSONL(t *testing.T) {
	records, err := ParseToolOutputLine("httpx", `{"url":"https://api.example.com","status_code":200}`)
	if err != nil {
		t.Fatal(err)
	}
	if records[0].Kind != KindHTTPTarget || records[0].Status != 200 {
		t.Fatalf("unexpected %#v", records[0])
	}
}

func TestParseKatanaNestedEndpoint(t *testing.T) {
	records, err := ParseToolOutputLine("katana", `{"request":{"endpoint":"https://api.example.com/v1/users"}}`)
	if err != nil {
		t.Fatal(err)
	}
	if records[0].URL != "https://api.example.com/v1/users" {
		t.Fatalf("unexpected %#v", records[0])
	}
}

func TestGFProducesOneRecordPerQueryParameter(t *testing.T) {
	records, err := ParseToolOutputLine("gf", "https://api.example.com/search?q=x&page=1")
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("expected two parameter records, got %#v", records)
	}
}

func TestArjunDocumentAdapter(t *testing.T) {
	records, err := ParseArjunDocument([]byte(`{"https://api.example.com/search":["q","page"]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || records[0].Kind != KindParameterizedURL {
		t.Fatalf("unexpected %#v", records)
	}
}

func TestNucleiAdapterKeepsEvidenceBounded(t *testing.T) {
	longResponse := strings.Repeat("x", 10000)
	line := `{"template-id":"test-template","matched-at":"https://api.example.com/v1","info":{"severity":"high"},"request":"GET /v1","response":"` + longResponse + `"}`
	records, err := ParseToolOutputLine("nuclei", line)
	if err != nil {
		t.Fatal(err)
	}
	if records[0].Kind != KindFinding || records[0].Severity != "high" {
		t.Fatalf("unexpected %#v", records[0])
	}
	if len(records[0].Evidence) >= len(longResponse) {
		t.Fatal("adapter failed to bound raw evidence")
	}
}

func TestRenderToolInputChecksContractBeforeFormatting(t *testing.T) {
	scope, _ := NewScope([]string{"example.com"}, nil, false)
	subfinder, _ := DefaultToolRegistry().MustGet("subfinder")
	socket := NewContractSocket(scope, subfinder)
	if _, err := RenderToolInput(socket, Record{Kind: KindURL, URL: "https://api.example.com/"}); err == nil {
		t.Fatal("URL should not be rendered into subfinder stdin")
	}
	line, err := RenderToolInput(socket, Record{Kind: KindDomain, Value: "Example.COM"})
	if err != nil {
		t.Fatal(err)
	}
	if line != "example.com\n" {
		t.Fatalf("unexpected rendered input %q", line)
	}
}
