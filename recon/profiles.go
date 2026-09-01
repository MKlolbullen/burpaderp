package recon

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

type InputMode string

const (
	InputStdin     InputMode = "stdin"
	InputPerTarget InputMode = "per_target_argument"
)

// CommandProfile pins the invocation shape that the adapter was written and
// tested for. ToolSpec says *what types* may cross a boundary; CommandProfile
// says *how this version-independent CLI surface is invoked*.
type CommandProfile struct {
	Tool        string        `json:"tool"`
	InputMode   InputMode     `json:"input_mode"`
	Args        []string      `json:"args"`
	TargetFlag  string        `json:"target_flag,omitempty"`
	Timeout     time.Duration `json:"timeout"`
	Description string        `json:"description,omitempty"`
}

func DefaultCommandProfiles() map[string]CommandProfile {
	profiles := []CommandProfile{
		{
			Tool: "subfinder", InputMode: InputPerTarget, TargetFlag: "-d",
			Args: []string{"-silent", "-json", "-disable-update-check"}, Timeout: 12 * time.Minute,
			Description: "passive enum, one scoped domain per process target argument",
		},
		{
			Tool: "puredns", InputMode: InputStdin,
			Args: []string{"resolve", "-q"}, Timeout: 15 * time.Minute,
			Description: "stdin resolve + wildcard/poisoning filter; quiet hostname output",
		},
		{
			Tool: "dnsx", InputMode: InputStdin,
			Args: []string{"-json", "-silent", "-a", "-aaaa", "-cname", "-omit-raw", "-disable-update-check"}, Timeout: 10 * time.Minute,
			Description: "stdin A/AAAA/CNAME enrichment to JSONL",
		},
		{
			Tool: "naabu", InputMode: InputStdin,
			Args: []string{"-json", "-silent", "-scan-type", "c", "-verify", "-rate", "100", "-disable-update-check"}, Timeout: 20 * time.Minute,
			Description: "explicit-network-scope TCP connect scan with conservative packet rate",
		},
		{
			Tool: "httpx", InputMode: InputStdin,
			Args: []string{"-json", "-silent", "-status-code", "-rate-limit", "50", "-threads", "20", "-follow-host-redirects", "-max-redirects", "5", "-disable-update-check"}, Timeout: 15 * time.Minute,
			Description: "HTTP probe with bounded concurrency and same-host redirects",
		},
		{
			Tool: "katana", InputMode: InputStdin,
			Args: []string{"-jsonl", "-silent", "-depth", "3", "-rate-limit", "20", "-concurrency", "5", "-parallelism", "5"}, Timeout: 20 * time.Minute,
			Description: "bounded active crawl using JSONL output",
		},
		{
			Tool: "gau", InputMode: InputStdin,
			Args: []string{"--threads", "5", "--timeout", "30"}, Timeout: 15 * time.Minute,
			Description: "historical/known URL providers; plain URL output",
		},
		{
			Tool: "nuclei", InputMode: InputStdin,
			Args: []string{"-jsonl", "-silent", "-no-color", "-rate-limit", "20", "-concurrency", "10", "-bulk-size", "10", "-disable-update-check"}, Timeout: 30 * time.Minute,
			Description: "template scan with conservative rate/concurrency; active permission required",
		},
	}
	out := make(map[string]CommandProfile, len(profiles))
	for _, profile := range profiles {
		out[profile.Tool] = profile
	}
	return out
}

func CommandProfileFor(tool string) (CommandProfile, bool) {
	profile, ok := DefaultCommandProfiles()[strings.ToLower(strings.TrimSpace(tool))]
	return profile, ok
}

func ListCommandProfiles() []CommandProfile {
	profiles := DefaultCommandProfiles()
	out := make([]CommandProfile, 0, len(profiles))
	for _, profile := range profiles {
		out = append(out, profile)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Tool < out[j].Tool })
	return out
}

func ValidateCommandProfile(profile CommandProfile, registry ToolRegistry) error {
	spec, ok := registry.Get(profile.Tool)
	if !ok {
		return fmt.Errorf("command profile references unknown tool %q", profile.Tool)
	}
	if profile.InputMode != InputStdin && profile.InputMode != InputPerTarget {
		return fmt.Errorf("%s has unsupported input mode %q", profile.Tool, profile.InputMode)
	}
	if profile.InputMode == InputPerTarget && profile.TargetFlag == "" {
		return fmt.Errorf("%s per-target profile requires target flag", profile.Tool)
	}
	if len(spec.Consumes) == 0 || len(spec.Produces) == 0 {
		return fmt.Errorf("%s must declare consume/produce contracts", profile.Tool)
	}
	if profile.Timeout <= 0 {
		return fmt.Errorf("%s profile timeout must be positive", profile.Tool)
	}
	return nil
}
