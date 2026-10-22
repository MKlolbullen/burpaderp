package main

import (
	"flag"
	"fmt"
	"io"

	recon "github.com/MKlolbullen/burpaderp/recon"
)

func runChain(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("chain", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	domain := fs.String("domain", "", "bare authorised domain")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments")
	}
	plan, err := recon.ReconChainPlan(*domain)
	if err != nil {
		return err
	}
	return writeJSON(out, plan)
}
