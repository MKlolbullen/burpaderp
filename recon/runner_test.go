package recon

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func TestRunExternalBoundsCapturedOutput(t *testing.T) {
	result, err := RunExternal(context.Background(), ExecRequest{
		Binary: os.Args[0],
		Args: []string{"-test.run=TestRunnerHelperProcess", "--"},
		Env: []string{"RECON_RUNNER_HELPER=output"},
		Limits: ExecLimits{Timeout: 2 * time.Second, MaxStdoutBytes: 64, MaxStderrBytes: 32},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.StdoutTruncated || len(result.Stdout) != 64 {
		t.Fatalf("stdout limit not enforced: len=%d truncated=%v", len(result.Stdout), result.StdoutTruncated)
	}
	if !result.StderrTruncated || len(result.Stderr) != 32 {
		t.Fatalf("stderr limit not enforced: len=%d truncated=%v", len(result.Stderr), result.StderrTruncated)
	}
}

func TestRunExternalEnforcesTimeout(t *testing.T) {
	_, err := RunExternal(context.Background(), ExecRequest{
		Binary: os.Args[0],
		Args: []string{"-test.run=TestRunnerHelperProcess", "--"},
		Env: []string{"RECON_RUNNER_HELPER=sleep"},
		Limits: ExecLimits{Timeout: 50 * time.Millisecond, MaxStdoutBytes: 1024, MaxStderrBytes: 1024},
	})
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("expected timeout error, got %v", err)
	}
}

func TestRunnerHelperProcess(t *testing.T) {
	mode := os.Getenv("RECON_RUNNER_HELPER")
	if mode == "" {
		return
	}
	switch mode {
	case "output":
		fmt.Fprint(os.Stdout, strings.Repeat("o", 256))
		fmt.Fprint(os.Stderr, strings.Repeat("e", 128))
		os.Exit(0)
	case "sleep":
		time.Sleep(5 * time.Second)
		os.Exit(0)
	default:
		os.Exit(2)
	}
}
