package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

type unreadableInput struct{}

func (unreadableInput) Read([]byte) (int, error) { panic("blocked producer must not wait for stdin") }

func TestRunRejectsTargetHTTPBeforeReadingInputWithEveryOptIn(t *testing.T) {
	for _, tool := range []string{"httpx", "katana", "nuclei"} {
		var out, errOut bytes.Buffer
		err := runTool([]string{"--tool", tool, "--scope-domain", "example.com", "--allow-active", "--allow-network", "--allow-derived-ips"},
			unreadableInput{}, &out, &errOut)
		if err == nil || !strings.Contains(err.Error(), "#44") || out.Len() != 0 {
			t.Fatalf("%s was not blocked: %v", tool, err)
		}
	}
}

func TestDoctorDistinguishesInstalledProfilesFromExecutionCapability(t *testing.T) {
	var out bytes.Buffer
	if err := runDoctor(&out); err != nil {
		t.Fatal(err)
	}
	var rows []doctorRow
	if err := json.Unmarshal(out.Bytes(), &rows); err != nil {
		t.Fatal(err)
	}
	blocked := 0
	for _, row := range rows {
		if row.Name == "httpx" || row.Name == "katana" || row.Name == "nuclei" {
			if !row.Profiled || !strings.Contains(row.ExecutionBlocked, "#44") {
				t.Fatalf("missing execution block: %+v", row)
			}
			blocked++
		}
	}
	if blocked != 3 {
		t.Fatalf("missing profiles: %d", blocked)
	}
}
