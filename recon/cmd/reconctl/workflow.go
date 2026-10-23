package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	recon "github.com/MKlolbullen/burpaderp/recon"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func runWorkflow(args []string, out, errOut io.Writer) error {
	fs := flag.NewFlagSet("workflow", flag.ContinueOnError)
	fs.SetOutput(errOut)
	domain := fs.String("domain", "", "bare target domain")
	dir := fs.String("output-dir", "", "exclusive per-domain/UUID output base")
	id := fs.String("run-id", "", "canonical UUID")
	hosts := fs.Int("max-hosts", 5000, "maximum hostnames")
	urls := fs.Int("max-urls", 10000, "maximum unique URLs")
	seconds := fs.Int("tool-timeout-seconds", 300, "per-tool seconds (5..1200)")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 || *seconds < 5 || *seconds > 1200 {
		return fmt.Errorf("invalid arguments or timeout")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	encoder := json.NewEncoder(out)
	encoder.SetEscapeHTML(false)
	_, err := recon.RunWorkflow(ctx, recon.WorkflowOptions{EnumerationOptions: recon.EnumerationOptions{Domain: *domain, OutputDir: *dir, RunID: *id, MaxHosts: *hosts, ToolTimeout: time.Duration(*seconds) * time.Second}, MaxURLs: *urls}, func(e recon.WorkflowEvent) error { return encoder.Encode(e) })
	return err
}
