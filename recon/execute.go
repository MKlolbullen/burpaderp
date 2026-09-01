package recon

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

type RunSummary struct {
	Tool             string        `json:"tool"`
	StartedAt        time.Time     `json:"started_at"`
	Duration         time.Duration `json:"duration"`
	InputAccepted    int           `json:"input_accepted"`
	InputRejected    int           `json:"input_rejected"`
	Executions       int           `json:"executions"`
	OutputAccepted   int           `json:"output_accepted"`
	OutputRejected   int           `json:"output_rejected"`
	StdoutTruncated  bool          `json:"stdout_truncated"`
	StderrTruncated  bool          `json:"stderr_truncated"`
}

// RunProfile executes one pinned command profile between the two typed sockets.
// It is intentionally a single-stage primitive: a DAG orchestrator can compose
// it, but no tool can bypass input validation or output adaptation when it does.
func RunProfile(ctx context.Context, scope Scope, toolName string, inputs []Record, policy RunPolicy, quarantine io.Writer) ([]Record, RunSummary, error) {
	started := time.Now()
	summary := RunSummary{Tool: strings.ToLower(strings.TrimSpace(toolName)), StartedAt: started.UTC()}
	registry := DefaultToolRegistry()
	spec, err := registry.MustGet(toolName)
	if err != nil {
		return nil, summary, err
	}
	if err := policy.Check(spec); err != nil {
		return nil, summary, err
	}
	profile, ok := CommandProfileFor(spec.Name)
	if !ok {
		return nil, summary, fmt.Errorf("tool %s has no executable command profile", spec.Name)
	}
	if err := ValidateCommandProfile(profile, registry); err != nil {
		return nil, summary, err
	}

	socket := NewContractSocket(scope, spec)
	var rejectEnc *json.Encoder
	if quarantine != nil {
		rejectEnc = json.NewEncoder(quarantine)
	}

	validated := make([]Record, 0, len(inputs))
	for _, record := range inputs {
		canonical, err := socket.Validate(DirectionInput, record)
		if err != nil {
			summary.InputRejected++
			r := record
			if qErr := writeRejected(rejectEnc, RejectedRecord{
				Tool: spec.Name, Direction: string(DirectionInput), Reason: err.Error(), Record: &r,
				Source: "RunProfile", CreatedAt: time.Now().UTC(),
			}); qErr != nil {
				return nil, summary, qErr
			}
			continue
		}
		validated = append(validated, canonical)
	}
	validated = DedupeRecords(validated)
	summary.InputAccepted = len(validated)
	if len(validated) == 0 {
		summary.Duration = time.Since(started)
		return nil, summary, errors.New("no valid input records remain after contract validation")
	}

	var output []Record
	var runErrors []error
	switch profile.InputMode {
	case InputStdin:
		var stdin bytes.Buffer
		for _, record := range validated {
			rendered, err := RenderToolInput(socket, record)
			if err != nil {
				runErrors = append(runErrors, err)
				continue
			}
			stdin.WriteString(rendered)
		}
		records, stats, result, err := executeOnce(ctx, socket, profile, profile.Args, stdin.Bytes(), quarantine)
		summary.Executions++
		summary.OutputAccepted += stats.Accepted
		summary.OutputRejected += stats.Rejected
		summary.StdoutTruncated = summary.StdoutTruncated || result.StdoutTruncated
		summary.StderrTruncated = summary.StderrTruncated || result.StderrTruncated
		output = append(output, records...)
		if err != nil {
			runErrors = append(runErrors, err)
			_ = quarantineProcessError(rejectEnc, spec.Name, err, result.Stderr)
		}

	case InputPerTarget:
		for _, record := range validated {
			rendered, err := RenderToolInput(socket, record)
			if err != nil {
				runErrors = append(runErrors, err)
				continue
			}
			target := strings.TrimSpace(rendered)
			args := append([]string(nil), profile.Args...)
			args = append(args, profile.TargetFlag, target)
			records, stats, result, err := executeOnce(ctx, socket, profile, args, nil, quarantine)
			summary.Executions++
			summary.OutputAccepted += stats.Accepted
			summary.OutputRejected += stats.Rejected
			summary.StdoutTruncated = summary.StdoutTruncated || result.StdoutTruncated
			summary.StderrTruncated = summary.StderrTruncated || result.StderrTruncated
			output = append(output, records...)
			if err != nil {
				runErrors = append(runErrors, err)
				_ = quarantineProcessError(rejectEnc, spec.Name, err, result.Stderr)
			}
		}
	default:
		return nil, summary, fmt.Errorf("unsupported input mode %q", profile.InputMode)
	}

	summary.Duration = time.Since(started)
	output = DedupeRecords(output)
	return output, summary, errors.Join(runErrors...)
}

func executeOnce(ctx context.Context, socket ContractSocket, profile CommandProfile, args []string, stdin []byte, quarantine io.Writer) ([]Record, SocketStats, ExecResult, error) {
	result, runErr := RunExternal(ctx, ExecRequest{
		Binary: socket.Tool.Binary,
		Args: args,
		Stdin: stdin,
		Limits: ExecLimits{
			Timeout: profile.Timeout,
			MaxStdoutBytes: DefaultExecLimits().MaxStdoutBytes,
			MaxStderrBytes: DefaultExecLimits().MaxStderrBytes,
		},
	})

	var normalized bytes.Buffer
	stats, adaptErr := AdaptToolOutput(socket, socket.Tool.Name, bytes.NewReader(result.Stdout), &normalized, quarantine)
	records, decodeErr := decodeRecordJSONL(normalized.Bytes())
	return records, stats, result, errors.Join(runErr, adaptErr, decodeErr)
}

func decodeRecordJSONL(data []byte) ([]Record, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64*1024), DefaultSocketLimits().MaxLineBytes)
	var out []Record
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var record Record
		if err := json.Unmarshal(line, &record); err != nil {
			return nil, fmt.Errorf("decode normalized record: %w", err)
		}
		out = append(out, record)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read normalized output: %w", err)
	}
	return out, nil
}

func quarantineProcessError(enc *json.Encoder, tool string, processErr error, stderr []byte) error {
	if processErr == nil {
		return nil
	}
	return writeRejected(enc, RejectedRecord{
		Tool: tool, Direction: string(DirectionOutput), Reason: "process: " + processErr.Error(),
		Raw: boundedRaw(string(stderr)), Source: "stderr", CreatedAt: time.Now().UTC(),
	})
}
