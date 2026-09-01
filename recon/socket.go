package recon

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

type Direction string

const (
	DirectionInput  Direction = "input"
	DirectionOutput Direction = "output"
)

type SocketLimits struct {
	MaxLineBytes int
	MaxRecords   int
}

func DefaultSocketLimits() SocketLimits {
	return SocketLimits{MaxLineBytes: 4 << 20, MaxRecords: 1_000_000}
}

type SocketStats struct {
	Accepted int `json:"accepted"`
	Rejected int `json:"rejected"`
}

// ContractSocket is the choke point between normalized records and a tool. It
// validates both directions: only compatible records may enter the process and
// only declared/canonical records may leave it.
type ContractSocket struct {
	Scope  Scope
	Tool   ToolSpec
	Limits SocketLimits
}

func NewContractSocket(scope Scope, tool ToolSpec) ContractSocket {
	return ContractSocket{Scope: scope, Tool: tool, Limits: DefaultSocketLimits()}
}

func (s ContractSocket) Validate(direction Direction, record Record) (Record, error) {
	if direction != DirectionInput && direction != DirectionOutput {
		return Record{}, fmt.Errorf("unknown socket direction %q", direction)
	}
	if direction == DirectionInput && !s.Tool.Accepts(record.Kind) {
		return Record{}, fmt.Errorf("%s cannot consume %s; accepts %v", s.Tool.Name, record.Kind, s.Tool.Consumes)
	}
	if direction == DirectionOutput && !s.Tool.ProducesKind(record.Kind) {
		return Record{}, fmt.Errorf("%s cannot produce %s; declares %v", s.Tool.Name, record.Kind, s.Tool.Produces)
	}
	validated, err := s.Scope.Validate(record)
	if err != nil {
		return Record{}, fmt.Errorf("%s %s contract: %w", s.Tool.Name, direction, err)
	}
	return validated, nil
}

// FilterJSONL validates a JSONL stream and emits canonical accepted records to
// accepted and all rejected/malformed values to quarantine. Bad data does not
// poison the remainder of the stream.
func (s ContractSocket) FilterJSONL(direction Direction, source string, in io.Reader, accepted, quarantine io.Writer) (SocketStats, error) {
	limits := s.Limits
	if limits.MaxLineBytes <= 0 {
		limits.MaxLineBytes = DefaultSocketLimits().MaxLineBytes
	}
	if limits.MaxRecords <= 0 {
		limits.MaxRecords = DefaultSocketLimits().MaxRecords
	}

	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 64*1024), limits.MaxLineBytes)
	outEnc := json.NewEncoder(accepted)
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
				Tool: s.Tool.Name, Direction: string(direction), Reason: "invalid JSON: " + err.Error(),
				Raw: boundedRaw(line), Source: source, CreatedAt: time.Now().UTC(),
			}); err != nil {
				return stats, err
			}
			continue
		}

		validated, err := s.Validate(direction, record)
		if err != nil {
			stats.Rejected++
			r := record
			if err := writeRejected(rejectEnc, RejectedRecord{
				Tool: s.Tool.Name, Direction: string(direction), Reason: err.Error(), Record: &r,
				Source: source, CreatedAt: time.Now().UTC(),
			}); err != nil {
				return stats, err
			}
			continue
		}
		if err := outEnc.Encode(validated); err != nil {
			return stats, fmt.Errorf("write accepted record: %w", err)
		}
		stats.Accepted++
	}
	if err := scanner.Err(); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "token too long") {
			return stats, fmt.Errorf("JSONL line exceeds %d-byte socket limit: %w", limits.MaxLineBytes, err)
		}
		return stats, fmt.Errorf("read JSONL stream: %w", err)
	}
	return stats, nil
}

func writeRejected(enc *json.Encoder, rejected RejectedRecord) error {
	if enc == nil {
		return nil
	}
	if err := enc.Encode(rejected); err != nil {
		return fmt.Errorf("write quarantine record: %w", err)
	}
	return nil
}

func boundedRaw(raw string) string {
	const max = 16 << 10
	if len(raw) <= max {
		return raw
	}
	return raw[:max] + "…[truncated]"
}
