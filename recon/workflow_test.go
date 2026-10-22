package recon

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func workflowFixtures(t *testing.T) {
	enumFixtures(t, map[string]string{
		"assetfinder": "printf '%s\\n' www.example.com b.example.com evil-example.com",
		"subfinder":   "printf '%s\\n' '{\"host\":\"www.example.com\"}'",
		"chaos":       "printf '%s\\n' api.example.com",
		"amass": `if [ "$1" = -version ]; then printf '%s\n' v3.23.3; exit; fi
[ "$*" = "enum -passive -nocolor -json - -dir . -d example.com" ] || exit 8
printf '%s\n' '{"name":"amass.example.com"}'`,
		"dnsx": `read first; [ "$first" = amass.example.com ] || exit 9
printf '%s\n' '{"host":"www.example.com","a":["93.184.216.34"],"cname":["cdn.outside.test"]}' '{"host":"outside.test","a":["93.184.216.34"]}'`,
		"waybackurls": `read domain; [ "$domain" = example.com ] || exit 10
printf '%s\n' 'https://www.example.com/a%2Fb?z=2&a=2&a=1#fragment' 'https://outside.test/no'`,
		"urlfinder": `[ "$*" = "-silent -j -all -disable-update-check -rl 5 -d example.com" ] || exit 11
printf '%s\n' '{"url":"https://www.example.com/a%2Fb?z=2&a=2&a=1"}' '{"url":"https://www.example.com/app.js?v=2"}'`,
		"waybackpy": `[ "$*" = "--cdx --match-type domain --collapse urlkey --cdx-print original --limit 25000 --url example.com" ] || exit 12
printf '%s\n' 'https://api.example.com/v1?b=%2f&a=+'`,
	})
}

func TestWorkflowRunsAllProviderDNSArchiveStagesAndPreservesSemantics(t *testing.T) {
	workflowFixtures(t)
	options := WorkflowOptions{EnumerationOptions: enumOptions(t), MaxURLs: 100}
	var events []WorkflowEvent
	summary, err := RunWorkflow(context.Background(), options, func(e WorkflowEvent) error { events = append(events, e); return nil })
	if err != nil || summary.State != "SUCCESS" || summary.Hosts != 5 || summary.Resolved != 1 || summary.URLs != 3 || len(summary.Tools) != 8 {
		t.Fatalf("%+v %v", summary, err)
	}
	dir := filepath.Join(options.OutputDir, "example.com", options.RunID)
	for _, name := range []string{"records.jsonl", "hosts.jsonl", "dns.jsonl", "archive-urls.jsonl", "urls.jsonl", "sorted_subs.txt", "sorted_urls.txt", "javascript-candidates.txt", "provenance.jsonl", "workflow-summary.json", "chain-plan.json"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatal(name, err)
		}
	}
	data, _ := os.ReadFile(filepath.Join(dir, "sorted_urls.txt"))
	if !strings.Contains(string(data), "/a%2Fb?z=2&a=2&a=1\n") || strings.Contains(string(data), "outside.test") {
		t.Fatal(string(data))
	}
	js, _ := os.ReadFile(filepath.Join(dir, "javascript-candidates.txt"))
	if string(js) != "https://www.example.com/app.js?v=2\n" {
		t.Fatal(string(js))
	}
	prov, _ := os.ReadFile(filepath.Join(dir, "provenance.jsonl"))
	provenance, err := decodeRecordJSONL(prov)
	if err != nil {
		t.Fatal(err)
	}
	sources := map[string]bool{}
	for _, r := range provenance {
		if r.URL == "https://www.example.com/a%2Fb?z=2&a=2&a=1" {
			sources[r.Tool] = true
		}
	}
	if !sources["waybackurls"] || !sources["urlfinder"] {
		t.Fatal("duplicate source provenance was lost")
	}
	if events[0].Type != "start" || events[len(events)-1].Type != "done" || events[len(events)-1].URLs != 3 {
		t.Fatal(events)
	}
	for _, e := range events {
		if e.Version != 2 || e.RunID != options.RunID || e.Domain != "example.com" {
			t.Fatal(e)
		}
	}
	if _, err := RunWorkflow(context.Background(), options, nil); err == nil {
		t.Fatal("overwrote run")
	}
}

func TestWorkflowMissingToolsAndHostURLCapsRemainExplicit(t *testing.T) {
	workflowFixtures(t)
	options := WorkflowOptions{EnumerationOptions: enumOptions(t), MaxURLs: 1}
	options.MaxHosts = 2
	summary, err := RunWorkflow(context.Background(), options, nil)
	if err != nil || summary.State != "PARTIAL" || !summary.Limited || summary.Hosts != 2 || summary.URLs != 1 {
		t.Fatalf("%+v %v", summary, err)
	}
}

func TestAmassVersionMismatchCannotStartEnumeration(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "enum-started")
	enumFixtures(t, map[string]string{"amass": "if [ \"$1\" = -version ]; then printf '%s\\n' v5.0.0; exit; fi\nprintf started > '" + marker + "'"})
	scope, _ := NewScope([]string{"example.com"}, nil, false)
	_, _, err := RunProfile(context.Background(), scope, "amass", []Record{{Kind: KindDomain, Value: "example.com"}}, DefaultRunPolicy(), "", nil)
	if err == nil || !strings.Contains(err.Error(), "exact version") {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("unverified amass enum ran")
	}
}

func TestWorkflowCancellationAndBrokenConsumerStopDownstreamJobs(t *testing.T) {
	workflowFixtures(t)
	options := WorkflowOptions{EnumerationOptions: enumOptions(t), MaxURLs: 100}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	summary, err := RunWorkflow(ctx, options, func(e WorkflowEvent) error {
		if e.Type == "tool" {
			cancel()
		}
		return nil
	})
	if err == nil || summary.State != "CANCELLED" || len(summary.Tools) != 1 {
		t.Fatalf("%+v %v", summary, err)
	}
	data, _ := os.ReadFile(filepath.Join(options.OutputDir, "example.com", options.RunID, "workflow-summary.json"))
	var saved WorkflowSummary
	if json.Unmarshal(data, &saved) != nil || saved.State != "CANCELLED" {
		t.Fatal(string(data))
	}
}

func TestURLCandidatesPreserveQueryOrderingEscapesAndRejectUserinfo(t *testing.T) {
	input := "HTTPS://WWW.Example.COM:443/a%2Fb/../c?b=%2f&a=+&a=%20#frag"
	want := "https://www.example.com/a%2Fb/../c?b=%2f&a=+&a=%20"
	for _, normalize := range []func(string) (string, error){NormalizeHTTPURL, func(s string) (string, error) { return CanonicalWorkflowURL(s, "example.com") }} {
		got, err := normalize(input)
		if err != nil || got != want {
			t.Fatalf("%q %v", got, err)
		}
	}
	for _, input := range []string{"https://u:p@example.com/", "https://evil-example.com/", "https://example.com:99999/", "file:///etc/passwd", "https://127.0.0.1/"} {
		if _, err := CanonicalWorkflowURL(input, "example.com"); err == nil {
			t.Fatal("accepted", input)
		}
	}
}

func TestAllNamedTargetCLIProfilesStayBlockedEvenWithEveryRiskOptIn(t *testing.T) {
	scope, _ := NewScope([]string{"example.com"}, nil, false)
	for _, tool := range []string{"httpx", "whatweb", "katana", "gospider", "cariddi", "jsfinder"} {
		_, summary, err := RunProfile(context.Background(), scope, tool, []Record{{Kind: KindURL, URL: "https://example.com/"}}, RunPolicy{true, true, true, true, true, true}, "", nil)
		if err == nil || !strings.Contains(err.Error(), "#44") || summary.Executions != 0 {
			t.Fatal(tool, summary, err)
		}
	}
}
