package recon

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestTargetHTTPProfilesCannotRunWithAllPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell marker fixture")
	}
	dir := t.TempDir()
	marker := filepath.Join(dir, "started")
	for _, tool := range []string{"httpx", "katana", "nuclei"} {
		if err := os.WriteFile(filepath.Join(dir, tool), []byte("#!/bin/sh\ntouch '"+marker+"'\n"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	scope, err := NewScope([]string{"example.com"}, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	policy := RunPolicy{true, true, true, true, true, true}
	for _, tool := range []string{"httpx", "katana", "nuclei"} {
		records, summary, err := RunProfile(context.Background(), scope, tool,
			[]Record{{Kind: KindURL, URL: "https://example.com/"}}, policy, "", nil)
		if err == nil || !strings.Contains(err.Error(), "#44") || summary.Executions != 0 || len(records) != 0 {
			t.Fatalf("%s escaped egress boundary: %v %+v", tool, err, summary)
		}
		// A future caller skipping RunProfile still cannot start the process.
		if _, err := runExternal(context.Background(), ExecRequest{Tool: tool}); err == nil || !strings.Contains(err.Error(), "#44") {
			t.Fatalf("low-level %s dispatch was allowed: %v", tool, err)
		}
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("blocked process started: %v", err)
	}
}

func TestOnlyExplicitNonTargetHTTPProfilesCanExecute(t *testing.T) {
	allowed := map[string]EgressClass{"amass": EgressProvider, "waybackurls": EgressProvider, "urlfinder": EgressProvider, "waybackpy": EgressProvider, "assetfinder": EgressProvider, "chaos": EgressProvider, "subfinder": EgressProvider, "gau": EgressProvider, "puredns": EgressDNS, "dnsx": EgressDNS, "naabu": EgressTCP}
	for _, spec := range DefaultToolRegistry().List() {
		err := CheckProfileEgress(spec.Name)
		want, ok := allowed[spec.Name]
		if ok {
			profile, exists := CommandProfileFor(spec.Name)
			if !exists || profile.Egress != want || err != nil {
				t.Fatalf("%s: %v %+v", spec.Name, err, profile)
			}
		} else if err == nil {
			t.Fatalf("unexpected external execution capability for %s", spec.Name)
		}
	}
	for _, tool := range []string{"", "unknown", "../subfinder"} {
		if _, err := runExternal(context.Background(), ExecRequest{Tool: tool}); err == nil {
			t.Fatalf("unknown tool allowed: %q", tool)
		}
	}
	if err := (RunPolicy{}).Check(ToolSpec{Name: "unknown"}); err == nil {
		t.Fatal("unknown risk must fail closed")
	}
}

func TestAllowedProviderProfileStillUsesTypedExecutionAndRunIdentity(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell provider fixture")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "subfinder"), []byte("#!/bin/sh\nprintf '%s\\n' '{\"host\":\"www.example.com\"}'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	scope, err := NewScope([]string{"example.com"}, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	runID := "123e4567-e89b-42d3-a456-426614174000"
	records, summary, err := RunProfile(context.Background(), scope, "subfinder", []Record{{Kind: KindDomain, Value: "example.com"}}, DefaultRunPolicy(), runID, nil)
	if err != nil || summary.Executions != 1 || len(records) != 1 || records[0].RunID != runID {
		t.Fatalf("provider typed execution regressed: %v %+v %+v", err, summary, records)
	}
}
