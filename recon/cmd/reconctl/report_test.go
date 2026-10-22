package main

import (
	"bytes"
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
