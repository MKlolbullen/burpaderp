package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestEnumerationCLIRejectsUnknownFlagsURLsAndExtraArguments(t *testing.T) {
	for _, args := range [][]string{{"--domain", "https://example.com"}, {"--domain", "example.com", "--tool", "httpx"}, {"--domain", "example.com", "extra"}, {"--domain", "example.com", "--max-hosts", "25001"}} {
		var out, stderr bytes.Buffer
		if err := runEnumerate(args, &out, &stderr); err == nil || out.Len() != 0 {
			t.Fatalf("accepted %v: %v %s", args, err, out.String())
		}
	}
}

func TestChainCLIPlansWithoutInstalledTools(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	var out bytes.Buffer
	if err := runChain([]string{"--domain", "Example.COM."}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"PLAN_ONLY"`) || !strings.Contains(out.String(), `"domain": "example.com"`) || !strings.Contains(out.String(), `"gospider"`) {
		t.Fatal(out.String())
	}
}
