package recon

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

func enumOptions(t *testing.T) EnumerationOptions {
	t.Helper()
	return EnumerationOptions{Domain: "Example.COM.", OutputDir: t.TempDir(), RunID: "123e4567-e89b-42d3-a456-426614174000", MaxHosts: 100, ToolTimeout: 5 * time.Second}
}

func enumFixtures(t *testing.T, scripts map[string]string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX executable fixtures")
	}
	dir := t.TempDir()
	for name, script := range scripts {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+script+"\n"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir)
	return dir
}

func TestEnumerationUsesPinnedArgvScopeDedupFilesAndBlockedHTTPX(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "httpx-started")
	enumFixtures(t, map[string]string{
		"assetfinder": `[ "$*" = "--subs-only example.com" ] || exit 7
printf '%s\n' 'Z.Example.com.' 'a.example.com' 'a.example.com' 'evil-example.com' '*.example.com' 'https://example.com'`,
		"subfinder": `[ "$*" = "-silent -json -all -recursive -disable-update-check -d example.com" ] || exit 8
printf '%s\n' '{"host":"b.example.com"}' '{"host":"a.example.com"}' '{"host":"outside.test"}'`,
		"chaos": `[ "$*" = "-silent -disable-update-check -d example.com" ] || exit 9
printf '%s\n' 'c.example.com'`,
		"httpx": "touch '" + marker + "'",
	})
	options := enumOptions(t)
	var events []EnumerationEvent
	summary, err := EnumerateDomain(context.Background(), options, func(e EnumerationEvent) error { events = append(events, e); return nil })
	if err != nil || summary.State != "SUCCESS" || summary.Count != 4 || len(summary.Tools) != 3 {
		t.Fatalf("%+v %v", summary, err)
	}
	dir := filepath.Join(options.OutputDir, "example.com", options.RunID)
	read := func(name string) string {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	if got := read("subs.txt"); got != "z.example.com\na.example.com\nb.example.com\nc.example.com\n" {
		t.Fatal(got)
	}
	if got := read("sorted_subs.txt"); got != "a.example.com\nb.example.com\nc.example.com\nz.example.com\n" {
		t.Fatal(got)
	}
	records, err := decodeRecordJSONL([]byte(read("hosts.jsonl")))
	if err != nil || len(records) != 4 {
		t.Fatalf("%+v %v", records, err)
	}
	for _, record := range records {
		if record.RunID != options.RunID || record.Kind != KindHostname || record.Tool == "" {
			t.Fatal(record)
		}
	}
	if !strings.Contains(read("httpx-plan.json"), `"BLOCKED"`) || !strings.Contains(read("httpx-plan.json"), `"-title"`) || strings.Contains(read("httpx-plan.json"), `"-follow-redirects"`) {
		t.Fatal("incorrect probe plan")
	}
	if !strings.Contains(read("chain-plan.json"), `"gospider"`) {
		t.Fatal("chain not persisted")
	}
	var saved EnumerationSummary
	if err := json.Unmarshal([]byte(read("summary.json")), &saved); err != nil || saved.Count != summary.Count {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("httpx launched")
	}
	if events[0].Type != "start" || events[len(events)-1].Type != "done" || events[len(events)-1].Count != 4 {
		t.Fatal(events)
	}
	if _, err := EnumerateDomain(context.Background(), options, nil); err == nil {
		t.Fatal("overwrote run")
	}
}

func TestEnumerationPartialFailureAndHostLimit(t *testing.T) {
	enumFixtures(t, map[string]string{"assetfinder": "printf '%s\\n' a.example.com b.example.com c.example.com", "subfinder": "exit 4", "chaos": "printf '%s\\n' d.example.com"})
	options := enumOptions(t)
	options.MaxHosts = 2
	summary, err := EnumerateDomain(context.Background(), options, nil)
	if err != nil || summary.State != "PARTIAL" || summary.Count != 2 || !summary.LimitReached || summary.Tools[1].State != "FAILED" {
		t.Fatalf("%+v %v", summary, err)
	}
}

func TestEnumerationMissingToolsFailExplicitly(t *testing.T) {
	enumFixtures(t, nil)
	summary, err := EnumerateDomain(context.Background(), enumOptions(t), nil)
	if err == nil || summary.State != "FAILED" || summary.Count != 0 || len(summary.Tools) != 3 {
		t.Fatalf("%+v %v", summary, err)
	}
}

func TestEnumerationTruncationCannotClaimCompleteResults(t *testing.T) {
	if _, err := os.Stat("/usr/bin/head"); err != nil {
		t.Skip("fixture requires head")
	}
	enumFixtures(t, map[string]string{"assetfinder": "printf '%s\\n' a.example.com\n/usr/bin/head -c 8388610 /dev/zero", "subfinder": "exit 0", "chaos": "exit 0"})
	summary, err := EnumerateDomain(context.Background(), enumOptions(t), nil)
	if err != nil || summary.State != "PARTIAL" || !summary.Tools[0].Run.StdoutTruncated || summary.Count != 1 {
		t.Fatalf("%+v %v", summary, err)
	}
}

func TestEnumerationNeverFollowsPreexistingRunSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink permissions")
	}
	options := enumOptions(t)
	root := filepath.Join(options.OutputDir, "example.com")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	other := t.TempDir()
	if err := os.Symlink(other, filepath.Join(root, options.RunID)); err != nil {
		t.Fatal(err)
	}
	if _, err := EnumerateDomain(context.Background(), options, nil); err == nil {
		t.Fatal("followed symlink")
	}
	entries, err := os.ReadDir(other)
	if err != nil || len(entries) != 0 {
		t.Fatal(entries, err)
	}
}

func TestEnumerationCancellationRetainsCollectedHostsAndStopsNextTools(t *testing.T) {
	enumFixtures(t, map[string]string{"assetfinder": "printf '%s\\n' a.example.com", "subfinder": "exec /bin/sleep 30", "chaos": "exit 0"})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	options := enumOptions(t)
	start := time.Now()
	summary, err := EnumerateDomain(ctx, options, func(e EnumerationEvent) error {
		if e.Type == "tool" {
			cancel()
		}
		return nil
	})
	if err == nil || summary.State != "CANCELLED" || summary.Count != 1 || len(summary.Tools) != 1 || time.Since(start) > 2*time.Second {
		t.Fatalf("%+v %v", summary, err)
	}
	data, err := os.ReadFile(filepath.Join(options.OutputDir, "example.com", options.RunID, "sorted_subs.txt"))
	if err != nil || string(data) != "a.example.com\n" {
		t.Fatalf("%s %v", data, err)
	}
}

func TestEnumerationParentDeadlineKillsRunningTool(t *testing.T) {
	enumFixtures(t, map[string]string{"assetfinder": "exec /bin/sleep 30"})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	summary, err := EnumerateDomain(ctx, enumOptions(t), nil)
	if err == nil || summary.State != "CANCELLED" || len(summary.Tools) != 1 || time.Since(start) > 3*time.Second {
		t.Fatalf("%+v %v", summary, err)
	}
}

func TestEnumerationBrokenEventConsumerPreventsLaunch(t *testing.T) {
	enumFixtures(t, nil)
	summary, err := EnumerateDomain(context.Background(), enumOptions(t), func(EnumerationEvent) error { return errors.New("closed pipe") })
	if err == nil || summary.State != "CANCELLED" || len(summary.Tools) != 0 {
		t.Fatalf("%+v %v", summary, err)
	}
}

func TestEnumerationRejectsInputBeforeFilesystemChanges(t *testing.T) {
	for _, domain := range []string{"", "https://example.com", "127.0.0.1", "1.2", "*.example.com", "-d.example.com", "example.com;id", "example.com/path", "éxample.com", "a..com", "example.com:443"} {
		options := enumOptions(t)
		options.Domain = domain
		if _, err := EnumerateDomain(context.Background(), options, nil); err == nil {
			t.Errorf("accepted %q", domain)
		}
		entries, _ := os.ReadDir(options.OutputDir)
		if len(entries) != 0 {
			t.Errorf("wrote files for %q", domain)
		}
	}
	for _, mutate := range []func(*EnumerationOptions){func(o *EnumerationOptions) { o.MaxHosts = 0 }, func(o *EnumerationOptions) { o.MaxHosts = 25001 }, func(o *EnumerationOptions) { o.ToolTimeout = time.Second }, func(o *EnumerationOptions) { o.ToolTimeout = 21 * time.Minute }, func(o *EnumerationOptions) { o.RunID = "../escape" }} {
		o := enumOptions(t)
		mutate(&o)
		if _, err := EnumerateDomain(context.Background(), o, nil); err == nil {
			t.Fatal("invalid bounds accepted")
		}
	}
}

func TestChainCatalogHasAllRequestedToolsAndAcyclicDependencies(t *testing.T) {
	plan, err := ReconChainPlan("Example.com.")
	if err != nil || plan["domain"] != "example.com" || plan["state"] != "PLAN_ONLY" {
		t.Fatal(plan, err)
	}
	seen := map[string]bool{}
	tools := map[string]string{}
	for _, raw := range plan["stages"].([]any) {
		stage := raw.(map[string]any)
		id := stage["id"].(string)
		if seen[id] {
			t.Fatal("duplicate stage")
		}
		for _, dep := range stage["depends_on"].([]any) {
			if !seen[dep.(string)] {
				t.Fatal("cycle or missing dependency", id, dep)
			}
		}
		seen[id] = true
		for _, rawTool := range stage["tools"].([]any) {
			tool := rawTool.(map[string]any)
			tools[tool["name"].(string)] = tool["mode"].(string)
		}
	}
	for _, name := range []string{"subfinder", "assetfinder", "chaos-client (chaos)", "amass", "dnsx", "whatweb", "httpx", "katana", "JSFinder", "gospider", "Waybackpy", "waybackurls", "urlfinder", "cariddi"} {
		if tools[name] == "" {
			t.Fatal("missing", name)
		}
	}
	var executable []string
	for name, mode := range tools {
		if mode == "ENUMERATION_JOB" {
			executable = append(executable, name)
		}
	}
	if len(executable) != 3 {
		t.Fatal(executable)
	}
	for _, name := range []string{"whatweb", "httpx", "katana", "JSFinder", "gospider", "cariddi"} {
		if tools[name] != "BLOCKED_TARGET_HTTP" || CheckProfileEgress(strings.ToLower(name)) == nil {
			t.Fatal("target process unlocked", name)
		}
	}
	profiles := DefaultCommandProfiles()
	if !reflect.DeepEqual(profiles["assetfinder"].Args, []string{"--subs-only"}) || profiles["assetfinder"].InputMode != InputPositional {
		t.Fatal("argv drift")
	}
}
