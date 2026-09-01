package recon

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

// RenderJSONLInputs is the tool's input socket: normalized JSONL enters, only
// records compatible with Tool.Consumes leave as canonical tool stdin lines.
func RenderJSONLInputs(socket ContractSocket, source string, in io.Reader, toolStdin, quarantine io.Writer) (SocketStats, error) {
	limits := effectiveSocketLimits(socket.Limits)
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 64*1024), limits.MaxLineBytes)
	var rejectEnc *json.Encoder
	if quarantine != nil {
		rejectEnc = json.NewEncoder(quarantine)
	}
	stats := SocketStats{}
	seen := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		seen++
		if seen > limits.MaxRecords {
			return stats, fmt.Errorf("record limit exceeded: %d", limits.MaxRecords)
		}
		var record Record
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			stats.Rejected++
			if err := writeRejected(rejectEnc, RejectedRecord{
				Tool: socket.Tool.Name, Direction: string(DirectionInput), Reason: "invalid JSON: " + err.Error(),
				Raw: boundedRaw(line), Source: source, CreatedAt: time.Now().UTC(),
			}); err != nil {
				return stats, err
			}
			continue
		}
		rendered, err := RenderToolInput(socket, record)
		if err != nil {
			stats.Rejected++
			r := record
			if err := writeRejected(rejectEnc, RejectedRecord{
				Tool: socket.Tool.Name, Direction: string(DirectionInput), Reason: err.Error(), Record: &r,
				Source: source, CreatedAt: time.Now().UTC(),
			}); err != nil {
				return stats, err
			}
			continue
		}
		if _, err := io.WriteString(toolStdin, rendered); err != nil {
			return stats, fmt.Errorf("write tool stdin: %w", err)
		}
		stats.Accepted++
	}
	if err := scanner.Err(); err != nil {
		return stats, fmt.Errorf("read normalized input: %w", err)
	}
	return stats, nil
}

// AdaptToolOutput is the tool's output socket: raw/machine-readable tool lines
// enter, the declared adapter converts them to Records, and only records that
// also pass Tool.Produces + scope/schema validation leave as normalized JSONL.
func AdaptToolOutput(socket ContractSocket, source string, in io.Reader, normalized, quarantine io.Writer) (SocketStats, error) {
	limits := effectiveSocketLimits(socket.Limits)
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 64*1024), limits.MaxLineBytes)
	outEnc := json.NewEncoder(normalized)
	var rejectEnc *json.Encoder
	if quarantine != nil {
		rejectEnc = json.NewEncoder(quarantine)
	}
	stats := SocketStats{}
	seen := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		seen++
		if seen > limits.MaxRecords {
			return stats, fmt.Errorf("record limit exceeded: %d", limits.MaxRecords)
		}
		records, err := ParseToolOutputLine(socket.Tool.Name, line)
		if err != nil {
			stats.Rejected++
			if err := writeRejected(rejectEnc, RejectedRecord{
				Tool: socket.Tool.Name, Direction: string(DirectionOutput), Reason: "adapter: " + err.Error(),
				Raw: boundedRaw(line), Source: source, CreatedAt: time.Now().UTC(),
			}); err != nil {
				return stats, err
			}
			continue
		}
		for _, record := range records {
			validated, err := socket.Validate(DirectionOutput, record)
			if err != nil {
				stats.Rejected++
				r := record
				if err := writeRejected(rejectEnc, RejectedRecord{
					Tool: socket.Tool.Name, Direction: string(DirectionOutput), Reason: err.Error(), Raw: boundedRaw(line),
					Record: &r, Source: source, CreatedAt: time.Now().UTC(),
				}); err != nil {
					return stats, err
				}
				continue
			}
			if err := outEnc.Encode(validated); err != nil {
				return stats, fmt.Errorf("write normalized output: %w", err)
			}
			stats.Accepted++
		}
	}
	if err := scanner.Err(); err != nil {
		return stats, fmt.Errorf("read tool output: %w", err)
	}
	return stats, nil
}

func effectiveSocketLimits(limits SocketLimits) SocketLimits {
	defaults := DefaultSocketLimits()
	if limits.MaxLineBytes <= 0 {
		limits.MaxLineBytes = defaults.MaxLineBytes
	}
	if limits.MaxRecords <= 0 {
		limits.MaxRecords = defaults.MaxRecords
	}
	return limits
}
