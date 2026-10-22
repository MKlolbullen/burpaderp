package recon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

var WorkflowTools = []string{"assetfinder", "subfinder", "chaos", "amass", "dnsx", "waybackurls", "urlfinder", "waybackpy"}

type WorkflowOptions struct {
	EnumerationOptions
	MaxURLs int
}
type WorkflowEvent struct {
	Version  int                    `json:"version"`
	Type     string                 `json:"type"`
	RunID    string                 `json:"run_id"`
	Domain   string                 `json:"domain"`
	State    string                 `json:"state,omitempty"`
	Hosts    int                    `json:"hosts"`
	URLs     int                    `json:"urls"`
	Resolved int                    `json:"resolved"`
	Tool     *EnumerationToolResult `json:"tool_result,omitempty"`
	Record   *Record                `json:"record,omitempty"`
}
type WorkflowSummary struct {
	Version         int                     `json:"version"`
	RunID           string                  `json:"run_id"`
	Domain          string                  `json:"domain"`
	State           string                  `json:"state"`
	Hosts           int                     `json:"hosts"`
	URLs            int                     `json:"urls"`
	Resolved        int                     `json:"resolved"`
	Limited         bool                    `json:"limited"`
	Tools           []EnumerationToolResult `json:"tools"`
	TargetExecution string                  `json:"target_execution"`
}

// RunWorkflow executes the provider/DNS branch and the local URL union. It does
// not launch target HTTP tools. The plugin can consume these artifacts through
// its mandatory native gateway for the following HTTP/crawl/JS phase.
func RunWorkflow(ctx context.Context, options WorkflowOptions, emit func(WorkflowEvent) error) (summary WorkflowSummary, resultErr error) {
	domain, err := EnumerationDomain(options.Domain)
	if err != nil {
		return summary, err
	}
	id, err := ResolveRunID(options.RunID)
	if err != nil {
		return summary, err
	}
	if options.MaxHosts < 1 || options.MaxHosts > MaxEnumerationHosts || options.MaxURLs < 1 || options.MaxURLs > 25000 {
		return summary, errors.New("host and URL limits must be 1..25000")
	}
	if options.ToolTimeout < 5*time.Second || options.ToolTimeout > 20*time.Minute {
		return summary, errors.New("tool timeout must be 5..1200 seconds")
	}
	if strings.TrimSpace(options.OutputDir) == "" {
		return summary, errors.New("output directory required")
	}
	if err := ctx.Err(); err != nil {
		return summary, err
	}
	base, err := filepath.Abs(options.OutputDir)
	if err != nil {
		return summary, err
	}
	root := filepath.Join(base, domain)
	if err := os.MkdirAll(root, 0o700); err != nil {
		return summary, err
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return summary, errors.New("domain output directory must be a real directory")
	}
	dir := filepath.Join(root, id)
	if err := os.Mkdir(dir, 0o700); err != nil {
		return summary, fmt.Errorf("create exclusive run directory: %w", err)
	}
	summary = WorkflowSummary{Version: 2, RunID: id, Domain: domain, State: "RUNNING", Tools: []EnumerationToolResult{}, TargetExecution: "Native Burp gateway phase is separate; external target CLI execution remains BLOCKED (#44)"}
	files := map[string]*os.File{}
	for _, name := range []string{"subs.txt", "hosts.jsonl", "dns.jsonl", "archive-urls.jsonl", "urls.jsonl", "records.jsonl", "provenance.jsonl"} {
		f, err := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			for _, f := range files {
				f.Close()
			}
			return summary, err
		}
		files[name] = f
	}
	hosts := map[string]Record{}
	urls := map[string]Record{}
	resolved := map[string]Record{}
	var eventErr error
	send := func(e WorkflowEvent) {
		if emit != nil && eventErr == nil {
			e.Version, e.RunID, e.Domain, e.Hosts, e.URLs, e.Resolved = 2, id, domain, len(hosts), len(urls), len(resolved)
			eventErr = emit(e)
		}
	}
	defer func() {
		summary.Hosts, summary.URLs, summary.Resolved = len(hosts), len(urls), len(resolved)
		var writes []error
		for _, f := range files {
			writes = append(writes, f.Sync(), f.Close())
		}
		list := func(values []string) []byte {
			sort.Strings(values)
			if len(values) == 0 {
				return nil
			}
			return []byte(strings.Join(values, "\n") + "\n")
		}
		hostNames := make([]string, 0, len(hosts))
		for name := range hosts {
			hostNames = append(hostNames, name)
		}
		urlNames := make([]string, 0, len(urls))
		var js []string
		for value := range urls {
			urlNames = append(urlNames, value)
			u, _ := url.Parse(value)
			path := strings.ToLower(u.Path)
			if strings.HasSuffix(path, ".js") || strings.HasSuffix(path, ".mjs") || strings.HasSuffix(path, ".cjs") {
				js = append(js, value)
			}
		}
		chain, _ := ReconChainPlan(domain)
		writes = append(writes, atomicEnumerationFile(dir, "sorted_subs.txt", list(hostNames)), atomicEnumerationFile(dir, "sorted_urls.txt", list(urlNames)), atomicEnumerationFile(dir, "javascript-candidates.txt", list(js)), writeEnumerationJSON(dir, "chain-plan.json", chain))
		if errors.Join(writes...) != nil {
			summary.State = "FAILED"
		}
		writes = append(writes, writeEnumerationJSON(dir, "workflow-summary.json", summary))
		writeErr := errors.Join(writes...)
		if writeErr == nil {
			send(WorkflowEvent{Type: "done", State: summary.State})
		}
		resultErr = errors.Join(resultErr, eventErr, writeErr)
	}()
	if err := writeEnumerationJSON(dir, "target.json", map[string]any{"domain": domain, "run_id": id, "max_hosts": options.MaxHosts, "max_urls": options.MaxURLs, "tool_timeout_seconds": options.ToolTimeout.Seconds()}); err != nil {
		summary.State = "FAILED"
		return summary, err
	}
	scope, _ := NewScope([]string{domain}, nil, false)
	send(WorkflowEvent{Type: "start", State: "RUNNING"})
	write := func(name string, r Record) error {
		encoder := json.NewEncoder(files[name])
		encoder.SetEscapeHTML(false)
		return encoder.Encode(r)
	}
	// Seed is a target candidate, not a discovered/resolved host or evidence of liveness.
	seed := Record{Kind: KindHostname, Value: domain, Hostname: domain, Tool: "seed", Source: "seed", RunID: id, CreatedAt: time.Now().UTC()}
	hosts[domain] = seed
	if _, err := fmt.Fprintln(files["subs.txt"], domain); err != nil {
		summary.State = "FAILED"
		return summary, err
	}
	if err := errors.Join(write("hosts.jsonl", seed), write("records.jsonl", seed)); err != nil {
		summary.State = "FAILED"
		return summary, err
	}
	send(WorkflowEvent{Type: "record", Record: &seed})
	successes := 0
	partial := false
	provenanceCount := 0
	for _, tool := range WorkflowTools {
		if ctx.Err() != nil || eventErr != nil {
			break
		}
		inputs := []Record{{Kind: KindDomain, Value: domain}}
		if tool == "dnsx" {
			inputs = nil
			names := make([]string, 0, len(hosts))
			for name := range hosts {
				names = append(names, name)
			}
			sort.Strings(names)
			for _, name := range names {
				inputs = append(inputs, hosts[name])
			}
		}
		stageDir := filepath.Join(dir, tool)
		if err := os.Mkdir(stageDir, 0o700); err != nil {
			summary.State = "FAILED"
			return summary, err
		}
		child, cancel := context.WithTimeout(ctx, options.ToolTimeout)
		records, run, runErr := RunProfileInDirectory(child, scope, tool, inputs, DefaultRunPolicy(), id, nil, stageDir)
		deadline := child.Err()
		cancel()
		status := EnumerationToolResult{Tool: tool, State: "SUCCESS", Message: "completed", Run: run}
		if runErr != nil {
			partial = true
			status.State, status.Message = "FAILED", "tool unavailable, unsupported version or provider failure"
			if deadline == context.DeadlineExceeded || errors.Is(runErr, context.DeadlineExceeded) {
				status.State, status.Message = "TIMEOUT", "tool time limit reached"
			}
			if ctx.Err() != nil {
				status.State = "CANCELLED"
			}
		} else {
			successes++
		}
		if run.StdoutTruncated || run.StderrTruncated {
			partial = true
			if runErr == nil {
				status.State, status.Message = "PARTIAL", "output capture limit reached"
			}
		}
		for _, r := range records {
			if eventErr != nil {
				break
			}
			r.RunID = id
			r.Tool = tool
			r.CreatedAt = time.Now().UTC()
			var destination string
			var duplicate, limited bool
			switch r.Kind {
			case KindHostname:
				name, e := EnumerationDomain(r.Hostname)
				if e != nil || !scope.InScopeHostname(name) {
					continue
				}
				r.Hostname, r.Value = name, name
				_, duplicate = hosts[name]
				limited = !duplicate && len(hosts) >= options.MaxHosts
				destination = "hosts.jsonl"
				if !duplicate && !limited {
					hosts[name] = r
					if _, err := fmt.Fprintln(files["subs.txt"], name); err != nil {
						summary.State = "FAILED"
						return summary, err
					}
				}
			case KindResolvedHost:
				if tool != "dnsx" {
					continue
				}
				if _, known := hosts[r.Hostname]; !known {
					continue
				}
				if len(r.Addresses) > 64 {
					r.Addresses = r.Addresses[:64]
					partial, summary.Limited = true, true
					status.State, status.Message = "PARTIAL", "DNS address metadata capped at 64 entries"
				}
				if len(r.CNAMEs) > 64 {
					r.CNAMEs = r.CNAMEs[:64]
					partial, summary.Limited = true, true
					status.State, status.Message = "PARTIAL", "DNS CNAME metadata capped at 64 entries"
				}
				_, duplicate = resolved[r.Hostname]
				limited = !duplicate && len(resolved) >= options.MaxHosts
				destination = "dns.jsonl"
				if !duplicate && !limited {
					resolved[r.Hostname] = r
				}
			case KindURL:
				canonical, e := CanonicalWorkflowURL(r.URL, domain)
				if e != nil {
					continue
				}
				r.URL, r.Value = canonical, canonical
				_, duplicate = urls[canonical]
				limited = !duplicate && len(urls) >= options.MaxURLs
				destination = "urls.jsonl"
				if !duplicate && !limited {
					urls[canonical] = r
				}
			default:
				continue
			}
			if limited {
				partial, summary.Limited = true, true
				continue
			}
			if provenanceCount < 5*options.MaxHosts+3*options.MaxURLs {
				if err := write("provenance.jsonl", r); err != nil {
					summary.State = "FAILED"
					return summary, err
				}
				provenanceCount++
			} else {
				partial, summary.Limited = true, true
			}
			if duplicate {
				continue
			}
			if err := errors.Join(write(destination, r), write("records.jsonl", r)); err != nil {
				summary.State = "FAILED"
				return summary, err
			}
			if r.Kind == KindURL {
				if err := write("archive-urls.jsonl", r); err != nil {
					summary.State = "FAILED"
					return summary, err
				}
			}
			status.Added++
			send(WorkflowEvent{Type: "record", Record: &r})
		}
		summary.Tools = append(summary.Tools, status)
		send(WorkflowEvent{Type: "tool", Tool: &status})
	}
	switch {
	case ctx.Err() != nil || eventErr != nil:
		summary.State = "CANCELLED"
		return summary, errors.Join(ctx.Err(), eventErr)
	case successes == 0:
		summary.State = "FAILED"
		return summary, errors.New("all workflow tools failed")
	case partial:
		summary.State = "PARTIAL"
	default:
		summary.State = "SUCCESS"
	}
	return summary, nil
}

// CanonicalWorkflowURL preserves escaped paths and the exact query ordering;
// resolving and re-encoding decoded paths would change the request semantics.
func CanonicalWorkflowURL(raw, domain string) (string, error) {
	if len(raw) > 8192 {
		return "", errors.New("HTTP URL exceeds 8192 bytes")
	}
	normalized, err := NormalizeHTTPURL(raw)
	if err != nil {
		return "", err
	}
	u, err := url.Parse(normalized)
	if err != nil || u.Hostname() == "" || u.User != nil || u.Opaque != "" {
		return "", errors.New("invalid HTTP URL")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", errors.New("non-HTTP URL")
	}
	host, err := EnumerationDomain(u.Hostname())
	if err != nil || !(host == domain || strings.HasSuffix(host, "."+domain)) {
		return "", errors.New("URL outside target domain")
	}
	port := u.Port()
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return "", errors.New("invalid port")
		}
	}
	u.Host = host
	if port != "" && !((u.Scheme == "https" && port == "443") || (u.Scheme == "http" && port == "80")) {
		u.Host += ":" + port
	}
	u.Fragment, u.RawFragment = "", ""
	if u.Path == "" {
		u.Path = "/"
	}
	return u.String(), nil
}
