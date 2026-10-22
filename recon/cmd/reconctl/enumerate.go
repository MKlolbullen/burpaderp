package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	recon "github.com/MKlolbullen/burpaderp/recon"
)

func runEnumerate(args []string, out, errOut io.Writer) error {
	fs := flag.NewFlagSet("enumerate", flag.ContinueOnError)
	fs.SetOutput(errOut)
	domain := fs.String("domain", "", "bare authorised domain")
	dir := fs.String("output-dir", "", "base output directory; each run creates domain/UUID")
	runID := fs.String("run-id", "", "optional canonical run UUID")
	maxHosts := fs.Int("max-hosts", 5000, "maximum unique hostnames (1..25000)")
	seconds := fs.Int("tool-timeout-seconds", 300, "per-tool deadline (5..1200 seconds)")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments")
	}
	if *seconds < 5 || *seconds > 1200 {
		return fmt.Errorf("tool timeout must be 5..1200 seconds")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	_, err := recon.EnumerateDomain(ctx, recon.EnumerationOptions{Domain: *domain, OutputDir: *dir,
		RunID: *runID, MaxHosts: *maxHosts, ToolTimeout: time.Duration(*seconds) * time.Second}, recon.EncodeEnumerationEvent(out))
	return err
}
