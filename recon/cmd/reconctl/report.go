package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	recon "github.com/MKlolbullen/burpaderp/recon"
	"io"
)

// WhatWeb writes a JSON report array. Its document boundary is distinct from
// line adapters; only validated normalised records reach stdout. No execution.
func runReport(args []string, in io.Reader, out, errOut io.Writer) error {
	cfg, err := parseContractArgs("adapt-report", args, false)
	if err != nil {
		return err
	}
	if cfg.socket.Tool.Name != "whatweb" {
		return fmt.Errorf("adapt-report currently requires --tool whatweb")
	}
	data, err := io.ReadAll(io.LimitReader(in, (8<<20)+1))
	if err != nil {
		return err
	}
	if len(data) > 8<<20 {
		return fmt.Errorf("report exceeds 8 MiB")
	}
	var entries []json.RawMessage
	if err := json.Unmarshal(data, &entries); err != nil {
		return err
	}
	if len(entries) > 25000 {
		return fmt.Errorf("report record limit")
	}
	var normalized bytes.Buffer
	encoder := json.NewEncoder(&normalized)
	for _, entry := range entries {
		records, err := recon.ParseToolOutputLine("whatweb", string(entry))
		if err != nil {
			return err
		}
		for _, r := range records {
			if err := encoder.Encode(r); err != nil {
				return err
			}
		}
	}
	quarantine, closeFn, err := openQuarantine(cfg.rejectsPath)
	if err != nil {
		return err
	}
	defer closeFn()
	stats, err := cfg.socket.FilterJSONL(recon.DirectionOutput, "whatweb-report", &normalized, out, quarantine)
	return finishStream(errOut, stats, err)
}
