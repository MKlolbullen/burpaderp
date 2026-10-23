package main

import (
	"bytes"
	"encoding/json"
	recon "github.com/MKlolbullen/burpaderp/recon"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWhatWebDocumentImportIsOfflineAndScopeChecked(t *testing.T) {
	input := `[{"target":"https://example.com/","http_status":200,"plugins":{"HTTPServer":{"string":["nginx"]}}},{"target":"https://outside.test/","http_status":200}]`
	var out, errOut bytes.Buffer
	if err := runReport([]string{"--tool", "whatweb", "--scope-domain", "example.com"}, strings.NewReader(input), &out, &errOut); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"status":200`) || strings.Contains(out.String(), "outside.test") {
		t.Fatal(out.String())
	}
}
func TestWorkflowCLIRejectsUnexpectedFlagsAndOverflowTimeout(t *testing.T) {
	for _, args := range [][]string{{"--domain", "https://example.com"}, {"--domain", "example.com", "--tool", "httpx"}, {"--domain", "example.com", "--tool-timeout-seconds", "9223372036854775807"}} {
		var out, stderr bytes.Buffer
		if err := runWorkflow(args, &out, &stderr); err == nil || out.Len() != 0 {
			t.Fatal(args, err)
		}
	}
}

func TestWhatWebBadEntriesAreQuarantinedWithoutDiscardingValidNeighbors(t *testing.T) {
	input := `[{"target":"https://example.com/first","http_status":200},{},{"target":"https://example.com/last","http_status":201},{"target":"https://outside.test/","http_status":200}]`
	path := filepath.Join(t.TempDir(), "rejects.jsonl")
	var out, stderr bytes.Buffer
	if err := runReport([]string{"--tool", "whatweb", "--scope-domain", "example.com", "--rejects", path}, strings.NewReader(input), &out, &stderr); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "/first") || !strings.Contains(out.String(), "/last") || strings.Contains(out.String(), "outside.test") {
		t.Fatal(out.String())
	}
	var stats recon.SocketStats
	if err := json.Unmarshal(stderr.Bytes(), &stats); err != nil || stats.Accepted != 2 || stats.Rejected != 2 {
		t.Fatal(stats, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatal(string(data))
	}
	var rejected recon.RejectedRecord
	if err := json.Unmarshal([]byte(lines[0]), &rejected); err != nil || rejected.Raw != "{}" || rejected.Tool != "whatweb" || rejected.Source != "whatweb-report" {
		t.Fatal(rejected, err)
	}
}

func TestWhatWebDocumentErrorsDoNotCreateQuarantineOrOutput(t *testing.T) {
	for _, input := range []string{`null`, `{}`, `[{"target":`, `"text"`} {
		path := filepath.Join(t.TempDir(), "rejects.jsonl")
		var out, stderr bytes.Buffer
		if err := runReport([]string{"--tool", "whatweb", "--scope-domain", "example.com", "--rejects", path}, strings.NewReader(input), &out, &stderr); err == nil {
			t.Fatal("expected document-level rejection")
		}
		if out.Len() != 0 {
			t.Fatal(out.String())
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("quarantine created for invalid document", err)
		}
	}
}
