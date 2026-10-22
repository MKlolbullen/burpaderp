package recon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const MaxEnumerationHosts = 25000

var enumerationTools = []string{"assetfinder", "subfinder", "chaos"}

type EnumerationOptions struct {
	Domain      string
	OutputDir   string
	RunID       string
	MaxHosts    int
	ToolTimeout time.Duration
}

type EnumerationToolResult struct {
	Tool    string     `json:"tool"`
	State   string     `json:"state"`
	Message string     `json:"message"`
	Added   int        `json:"added"`
	Run     RunSummary `json:"run"`
}

// EnumerationEvent is the versioned GUI protocol. hosts.jsonl separately contains
// ordinary Record values, consumable by the existing scope-checked Burp importer.
type EnumerationEvent struct {
	Version int                    `json:"version"`
	Type    string                 `json:"type"`
	RunID   string                 `json:"run_id"`
	Domain  string                 `json:"domain"`
	State   string                 `json:"state,omitempty"`
	Count   int                    `json:"count"`
	Tool    *EnumerationToolResult `json:"tool_result,omitempty"`
	Record  *Record                `json:"record,omitempty"`
}

type EnumerationSummary struct {
	Version      int                     `json:"version"`
	RunID        string                  `json:"run_id"`
	Domain       string                  `json:"domain"`
	State        string                  `json:"state"`
	Count        int                     `json:"count"`
	HostLimit    int                     `json:"host_limit"`
	LimitReached bool                    `json:"limit_reached"`
	ToolSeconds  float64                 `json:"tool_timeout_seconds"`
	Tools        []EnumerationToolResult `json:"tools"`
	HTTPX        HTTPXPlan               `json:"httpx"`
}

type HTTPXPlan struct {
	State   string   `json:"state"`
	Reason  string   `json:"reason"`
	Command []string `json:"command"`
}

// EnumerationDomain accepts a bare ASCII/punycode DNS name, never a URL, IP,
// option or shell expression. A numeric final label is excluded on both sides
// of the GUI boundary (including IPv4 shorthand).
func EnumerationDomain(raw string) (string, error) {
	domain, err := NormalizeFQDN(raw)
	if err != nil {
		return "", fmt.Errorf("enter a bare ASCII/punycode domain")
	}
	_, ipErr := netip.ParseAddr(domain)
	top := domain[strings.LastIndex(domain, ".")+1:]
	if ipErr == nil || strings.Trim(top, "0123456789") == "" {
		return "", fmt.Errorf("an IP address is not an enumeration domain")
	}
	return domain, nil
}

// EnumerateDomain composes only pinned provider profiles; it never executes
// httpx. Installed provider binaries are trusted, not OS-sandboxed. Event errors
// stop further launches, while successfully collected files remain available.
func EnumerateDomain(ctx context.Context, options EnumerationOptions, emit func(EnumerationEvent) error) (summary EnumerationSummary, resultErr error) {
	domain, err := EnumerationDomain(options.Domain)
	if err != nil {
		return summary, err
	}
	runID, err := ResolveRunID(options.RunID)
	if err != nil {
		return summary, err
	}
	if options.MaxHosts < 1 || options.MaxHosts > MaxEnumerationHosts {
		return summary, fmt.Errorf("max hosts must be 1..%d", MaxEnumerationHosts)
	}
	if options.ToolTimeout < 5*time.Second || options.ToolTimeout > 20*time.Minute {
		return summary, fmt.Errorf("tool timeout must be 5..1200 seconds")
	}
	if strings.TrimSpace(options.OutputDir) == "" {
		return summary, errors.New("output directory is required")
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
	dir := filepath.Join(root, runID)
	// A reused UUID, including a pre-existing symlink, must never overwrite a run.
	if err := os.Mkdir(dir, 0o700); err != nil {
		return summary, fmt.Errorf("create exclusive run directory: %w", err)
	}
	file, err := os.OpenFile(filepath.Join(dir, "subs.txt"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return summary, err
	}
	defer file.Close()
	hosts, err := os.OpenFile(filepath.Join(dir, "hosts.jsonl"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return summary, err
	}
	defer hosts.Close()
	profile, _ := CommandProfileFor("httpx")
	plan := HTTPXPlan{State: "BLOCKED", Reason: CheckProfileEgress("httpx").Error(),
		Command: append(append([]string{"httpx"}, profile.Args...), "-list", "sorted_subs.txt", "-output", "httpx.jsonl")}
	chain, err := ReconChainPlan(domain)
	if err != nil {
		return summary, err
	}
	if err := writeEnumerationJSON(dir, "target.json", map[string]any{"domain": domain, "run_id": runID, "max_hosts": options.MaxHosts, "tool_timeout_seconds": options.ToolTimeout.Seconds()}); err != nil {
		return summary, err
	}
	summary = EnumerationSummary{Version: 1, RunID: runID, Domain: domain, State: "RUNNING",
		HostLimit: options.MaxHosts, ToolSeconds: options.ToolTimeout.Seconds(), Tools: []EnumerationToolResult{}, HTTPX: plan}
	seen := map[string]bool{}
	var streamErr error
	send := func(event EnumerationEvent) {
		if emit == nil || streamErr != nil {
			return
		}
		event.Version, event.RunID, event.Domain, event.Count = 1, runID, domain, len(seen)
		streamErr = emit(event)
	}
	// Finalise even after cancellation or a broken GUI pipe. A failed final write
	// cannot produce a successful terminal event.
	defer func() {
		summary.Count = len(seen)
		names := make([]string, 0, len(seen))
		for name := range seen {
			names = append(names, name)
		}
		sort.Strings(names)
		var sorted string
		if len(names) > 0 {
			sorted = strings.Join(names, "\n") + "\n"
		}
		writeErr := errors.Join(file.Sync(), hosts.Sync(), atomicEnumerationFile(dir, "sorted_subs.txt", []byte(sorted)), writeEnumerationJSON(dir, "httpx-plan.json", plan), writeEnumerationJSON(dir, "chain-plan.json", chain))
		if writeErr != nil {
			summary.State = "FAILED"
		}
		writeErr = errors.Join(writeErr, writeEnumerationJSON(dir, "summary.json", summary))
		if writeErr != nil {
			summary.State = "FAILED"
		}
		if writeErr == nil {
			send(EnumerationEvent{Type: "done", State: summary.State})
		}
		resultErr = errors.Join(resultErr, streamErr, writeErr)
	}()
	send(EnumerationEvent{Type: "start", State: "RUNNING"})
	scope, _ := NewScope([]string{domain}, nil, false)
	successes := 0
	partial := false
	for _, tool := range enumerationTools {
		if ctx.Err() != nil || streamErr != nil {
			break
		}
		child, cancel := context.WithTimeout(ctx, options.ToolTimeout)
		records, run, runErr := RunProfile(child, scope, tool, []Record{{Kind: KindDomain, Value: domain}}, DefaultRunPolicy(), runID, nil)
		childErr := child.Err()
		cancel()
		status := EnumerationToolResult{Tool: tool, State: "SUCCESS", Message: "completed", Run: run}
		if runErr != nil {
			status.State, status.Message = "FAILED", "tool unavailable or failed; check installation/provider configuration"
			if childErr == context.DeadlineExceeded || errors.Is(runErr, context.DeadlineExceeded) {
				status.State, status.Message = "TIMEOUT", "tool time limit reached"
			}
			if ctx.Err() != nil {
				status.State, status.Message = "CANCELLED", "cancelled"
			}
			partial = true
		} else {
			successes++
		}
		if run.StdoutTruncated || run.StderrTruncated {
			partial = true
			if runErr == nil {
				status.State, status.Message = "PARTIAL", "tool output limit reached"
			}
		}
		for _, record := range records {
			name, nameErr := EnumerationDomain(record.Hostname)
			if nameErr != nil || record.Kind != KindHostname || !scope.InScopeHostname(name) || seen[name] {
				continue
			}
			if len(seen) >= options.MaxHosts {
				summary.LimitReached, partial = true, true
				continue
			}
			canonical := Record{Kind: KindHostname, Value: name, Hostname: name, Tool: tool, Source: tool, RunID: runID, CreatedAt: time.Now().UTC()}
			if _, err := fmt.Fprintln(file, name); err != nil {
				summary.State = "FAILED"
				return summary, err
			}
			if err := json.NewEncoder(hosts).Encode(canonical); err != nil {
				summary.State = "FAILED"
				return summary, err
			}
			seen[name] = true
			status.Added++
			send(EnumerationEvent{Type: "host", Record: &canonical})
		}
		summary.Tools = append(summary.Tools, status)
		send(EnumerationEvent{Type: "tool", Tool: &status})
	}
	switch {
	case ctx.Err() != nil || streamErr != nil:
		summary.State = "CANCELLED"
		return summary, errors.Join(ctx.Err(), streamErr)
	case successes == 0 && len(seen) == 0:
		summary.State = "FAILED"
		return summary, errors.New("all enumeration tools failed")
	case partial:
		summary.State = "PARTIAL"
	default:
		summary.State = "SUCCESS"
	}
	return summary, nil
}

func writeEnumerationJSON(dir, name string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return atomicEnumerationFile(dir, name, append(data, '\n'))
}

func atomicEnumerationFile(dir, name string, data []byte) error {
	file, err := os.OpenFile(filepath.Join(dir, name+".tmp"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(data)
	err = errors.Join(writeErr, file.Sync(), file.Close())
	if err != nil {
		return err
	}
	return os.Rename(file.Name(), filepath.Join(dir, name))
}

// EncodeEnumerationEvent deliberately exposes only the bounded protocol, never
// raw stderr or arbitrary provider text.
func EncodeEnumerationEvent(out io.Writer) func(EnumerationEvent) error {
	encoder := json.NewEncoder(out)
	return func(event EnumerationEvent) error { return encoder.Encode(event) }
}
