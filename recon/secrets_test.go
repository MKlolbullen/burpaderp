package recon

import (
	"strings"
	"testing"
)

func TestParseGitleaksReportDocument(t *testing.T) {
	report := `[{"Description":"AWS Access Key","StartLine":12,"EndLine":12,"Match":"key = AKIAABCDEFGHIJKLMNOP","Secret":"AKIAABCDEFGHIJKLMNOP","File":"config/prod.env","Commit":"deadbeef","RuleID":"aws-access-token","Fingerprint":"config/prod.env:aws-access-token:12"}]`
	records, err := ParseGitleaksReport([]byte(report))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("expected one finding, got %#v", records)
	}
	r := records[0]
	if r.Kind != KindFinding || r.Tool != "gitleaks" || r.Severity != "high" {
		t.Fatalf("unexpected finding %#v", r)
	}
	if r.Value != "config/prod.env:12" {
		t.Fatalf("unexpected anchor value %q", r.Value)
	}
	if !strings.Contains(r.Evidence, "rule=aws-access-token") || !strings.Contains(r.Evidence, "commit=deadbeef") {
		t.Fatalf("evidence missing provenance: %q", r.Evidence)
	}
}

func TestParseGitleaksReportBoundsMatchEvidence(t *testing.T) {
	long := strings.Repeat("x", 9000)
	report := `[{"RuleID":"generic","File":"a.txt","Match":"` + long + `"}]`
	records, err := ParseGitleaksReport([]byte(report))
	if err != nil {
		t.Fatal(err)
	}
	if len(records[0].Evidence) >= len(long) {
		t.Fatal("gitleaks adapter failed to bound raw match evidence")
	}
}

func TestParseGitleaksReportEmptyArray(t *testing.T) {
	records, err := ParseGitleaksReport([]byte(`[]`))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 0 {
		t.Fatalf("expected no findings, got %#v", records)
	}
}

func TestGitleaksIsNotParsedAsJSONL(t *testing.T) {
	if _, err := ParseToolOutputLine("gitleaks", `{"RuleID":"x","File":"a"}`); err == nil {
		t.Fatal("gitleaks must be parsed via ParseGitleaksReport, not the JSONL line adapter")
	}
}

func TestParseTrufflehogVerifiedGitFinding(t *testing.T) {
	line := `{"SourceMetadata":{"Data":{"Git":{"commit":"fbc14303","file":"keys","repository":"https://github.com/example/test_keys","line":4}}},"SourceName":"trufflehog - git","DetectorName":"AWS","DecoderName":"PLAIN","Verified":true,"Raw":"AKIA","Redacted":"AKIAYVP4CIPPERUVIFXG"}`
	records, err := ParseToolOutputLine("trufflehog", line)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("expected one finding, got %#v", records)
	}
	r := records[0]
	if r.Kind != KindFinding || r.Tool != "trufflehog" || r.Severity != "high" {
		t.Fatalf("unexpected finding %#v", r)
	}
	if r.Value != "https://github.com/example/test_keys#keys:4" {
		t.Fatalf("unexpected anchor value %q", r.Value)
	}
	if !strings.Contains(r.Evidence, "verified=true") || !strings.Contains(r.Evidence, "detector=AWS") {
		t.Fatalf("unexpected evidence %q", r.Evidence)
	}
}

func TestParseTrufflehogUnverifiedFilesystemFinding(t *testing.T) {
	line := `{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/postleaks/req-1.json"}}},"SourceName":"trufflehog - filesystem","DetectorName":"Stripe","DecoderName":"PLAIN","Verified":false,"Redacted":"sk_live_***"}`
	records, err := ParseToolOutputLine("trufflehog", line)
	if err != nil {
		t.Fatal(err)
	}
	r := records[0]
	if r.Severity != "medium" {
		t.Fatalf("unverified secret should be medium, got %q", r.Severity)
	}
	if r.Value != "/tmp/postleaks/req-1.json" {
		t.Fatalf("unexpected anchor value %q", r.Value)
	}
}

func TestTrufflehogFindingPassesOutputContract(t *testing.T) {
	scope, err := NewScope([]string{"example.com"}, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := DefaultToolRegistry().MustGet("trufflehog")
	if err != nil {
		t.Fatal(err)
	}
	socket := NewContractSocket(scope, spec)
	records, err := ParseToolOutputLine("trufflehog", `{"SourceMetadata":{"Data":{"Git":{"file":"keys","repository":"https://github.com/example/test_keys"}}},"DetectorName":"AWS","Verified":true}`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := socket.Validate(DirectionOutput, records[0]); err != nil {
		t.Fatalf("trufflehog finding rejected by output contract: %v", err)
	}
}

func TestParseTrufflehogRejectsEmptyMetadata(t *testing.T) {
	if _, err := ParseToolOutputLine("trufflehog", `{"Verified":false}`); err == nil {
		t.Fatal("trufflehog record with no detector/source must be rejected")
	}
}
