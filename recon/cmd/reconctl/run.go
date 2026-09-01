package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	recon "github.com/MKlolbullen/burpaderp/recon"
)

type runCLIStats struct {
	InputSocket recon.SocketStats `json:"input_socket"`
	Run         recon.RunSummary  `json:"run"`
}

func runTool(args []string, in io.Reader, out, errOut io.Writer) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	toolName := fs.String("tool", "", "pinned command profile to execute")
	var domains stringList
	var cidrs stringList
	fs.Var(&domains, "scope-domain", "authorised domain/FQDN (repeatable)")
	fs.Var(&cidrs, "scope-cidr", "authorised CIDR; use /32 or /128 for one IP (repeatable)")
	allowDerived := fs.Bool("allow-derived-ips", false, "permit network probing DNS-derived IPs")
	allowNetwork := fs.Bool("allow-network", false, "enable network_probe tools such as naabu")
	allowActive := fs.Bool("allow-active", false, "enable active_fuzz/vulnerability tools such as nuclei")
	rejectsPath := fs.String("rejects", "", "quarantine JSONL path")
	maxLine := fs.Int("max-line-bytes", 4<<20, "maximum normalized input record size")
	maxRecords := fs.Int("max-records", 1_000_000, "maximum normalized input records")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *toolName == "" {
		return fmt.Errorf("--tool is required")
	}

	registry := recon.DefaultToolRegistry()
	spec, err := registry.MustGet(*toolName)
	if err != nil {
		return err
	}
	if _, ok := recon.CommandProfileFor(spec.Name); !ok {
		return fmt.Errorf("tool %s has no pinned executable profile", spec.Name)
	}
	scope, err := recon.NewScope(domains, cidrs, *allowDerived)
	if err != nil {
		return err
	}
	quarantine, closeFn, err := openQuarantine(*rejectsPath)
	if err != nil {
		return err
	}
	defer closeFn()

	// First socket: malformed JSON, wrong record kinds and scope violations are
	// quarantined before a process is even allowed to start.
	socket := recon.NewContractSocket(scope, spec)
	socket.Limits = recon.SocketLimits{MaxLineBytes: *maxLine, MaxRecords: *maxRecords}
	var canonical bytes.Buffer
	inputStats, err := socket.FilterJSONL(recon.DirectionInput, "reconctl-run", in, &canonical, quarantine)
	if err != nil {
		return err
	}
	inputs, err := decodeCLIRecords(canonical.Bytes())
	if err != nil {
		return err
	}

	policy := recon.DefaultRunPolicy()
	policy.AllowNetworkProbe = *allowNetwork
	policy.AllowActiveFuzz = *allowActive

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	results, summary, runErr := recon.RunProfile(ctx, scope, spec.Name, inputs, policy, quarantine)
	enc := json.NewEncoder(out)
	for _, record := range results {
		if err := enc.Encode(record); err != nil {
			return fmt.Errorf("write normalized result: %w", err)
		}
	}
	if err := writeJSON(errOut, runCLIStats{InputSocket: inputStats, Run: summary}); err != nil && runErr == nil {
		return err
	}
	return runErr
}

func decodeCLIRecords(data []byte) ([]recon.Record, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	var records []recon.Record
	for {
		var record recon.Record
		err := dec.Decode(&record)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("decode canonical input: %w", err)
		}
		records = append(records, record)
	}
	return records, nil
}
