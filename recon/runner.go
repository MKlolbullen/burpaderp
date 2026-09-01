package recon

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"
)

type ExecLimits struct {
	Timeout        time.Duration
	MaxStdoutBytes int64
	MaxStderrBytes int64
}

func DefaultExecLimits() ExecLimits {
	return ExecLimits{
		Timeout: 15 * time.Minute,
		MaxStdoutBytes: 128 << 20,
		MaxStderrBytes: 8 << 20,
	}
}

type ExecRequest struct {
	Binary string
	Args   []string
	Stdin  []byte
	Env    []string
	Dir    string
	Limits ExecLimits
}

type ExecResult struct {
	ExitCode        int           `json:"exit_code"`
	Duration        time.Duration `json:"duration"`
	Stdout          []byte        `json:"-"`
	Stderr          []byte        `json:"-"`
	StdoutTruncated bool          `json:"stdout_truncated"`
	StderrTruncated bool          `json:"stderr_truncated"`
}

// RunExternal starts a binary directly; it never passes command text through a
// shell. This keeps tool arguments structurally separate from user/target data
// and makes command injection a much smaller problem than string-built pipelines.
func RunExternal(parent context.Context, request ExecRequest) (ExecResult, error) {
	if request.Binary == "" {
		return ExecResult{}, errors.New("binary is required")
	}
	limits := request.Limits
	defaults := DefaultExecLimits()
	if limits.Timeout <= 0 {
		limits.Timeout = defaults.Timeout
	}
	if limits.MaxStdoutBytes <= 0 {
		limits.MaxStdoutBytes = defaults.MaxStdoutBytes
	}
	if limits.MaxStderrBytes <= 0 {
		limits.MaxStderrBytes = defaults.MaxStderrBytes
	}

	ctx, cancel := context.WithTimeout(parent, limits.Timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, request.Binary, request.Args...)
	cmd.Stdin = bytes.NewReader(request.Stdin)
	if request.Dir != "" {
		cmd.Dir = request.Dir
	}
	if request.Env != nil {
		cmd.Env = append(os.Environ(), request.Env...)
	}
	stdout := newCappedBuffer(limits.MaxStdoutBytes)
	stderr := newCappedBuffer(limits.MaxStderrBytes)
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	start := time.Now()
	err := cmd.Run()
	result := ExecResult{
		ExitCode: exitCode(err),
		Duration: time.Since(start),
		Stdout: append([]byte(nil), stdout.Bytes()...),
		Stderr: append([]byte(nil), stderr.Bytes()...),
		StdoutTruncated: stdout.Truncated(),
		StderrTruncated: stderr.Truncated(),
	}

	if ctx.Err() == context.DeadlineExceeded {
		return result, fmt.Errorf("%s timed out after %s", request.Binary, limits.Timeout)
	}
	if err != nil {
		return result, fmt.Errorf("%s exited with code %d: %w", request.Binary, result.ExitCode, err)
	}
	return result, nil
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return -1
}

type cappedBuffer struct {
	limit     int64
	written   int64
	truncated bool
	buf       bytes.Buffer
}

func newCappedBuffer(limit int64) *cappedBuffer { return &cappedBuffer{limit: limit} }

// Write always reports the full input consumed so the child process cannot
// deadlock on a full pipe. Bytes beyond the cap are discarded and flagged.
func (b *cappedBuffer) Write(p []byte) (int, error) {
	original := len(p)
	remaining := b.limit - b.written
	if remaining > 0 {
		keep := int64(len(p))
		if keep > remaining {
			keep = remaining
		}
		_, _ = b.buf.Write(p[:int(keep)])
		b.written += keep
	}
	if int64(original) > remaining {
		b.truncated = true
	}
	return original, nil
}

func (b *cappedBuffer) Bytes() []byte { return b.buf.Bytes() }
func (b *cappedBuffer) Truncated() bool { return b.truncated }
