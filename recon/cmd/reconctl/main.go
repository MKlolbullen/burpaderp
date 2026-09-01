package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	recon "github.com/MKlolbullen/burpaderp/recon"
)

func main() {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "doctor":
		err = runDoctor(os.Stdout)
	case "plan":
		err = runPlan(os.Stdout)
	case "edge":
		err = runEdge(os.Args[2:], os.Stdout)
	case "socket":
		err = runSocket(os.Args[2:], os.Stdin, os.Stdout, os.Stderr)
	case "help", "-h", "--help":
		usage(os.Stdout)
		return
	default:
		usage(os.Stderr)
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "reconctl:", err)
		os.Exit(1)
	}
}

func usage(w io.Writer) {
	fmt.Fprintln(w, `reconctl - typed external-tool contract gate for Recon Hound

Usage:
  reconctl doctor
  reconctl plan
  reconctl edge --from httpx --to katana
  reconctl socket --tool <name> --direction input|output \
      --scope-domain example.com [--scope-cidr 203.0.113.0/24] \
      [--allow-derived-ips] [--rejects rejects.jsonl]

The socket command reads normalized Record JSONL on stdin, writes only canonical
compatible records on stdout, and quarantines malformed/incompatible records.
It does not execute the target tool; execution adapters sit on either side of
this gate.`)
}

type doctorRow struct {
	Name     string          `json:"name"`
	Binary   string          `json:"binary"`
	Found    bool            `json:"found"`
	Path     string          `json:"path,omitempty"`
	Consumes []recon.Kind    `json:"consumes"`
	Produces []recon.Kind    `json:"produces"`
	Risk     recon.RiskClass `json:"risk"`
}

func runDoctor(w io.Writer) error {
	registry := recon.DefaultToolRegistry()
	rows := make([]doctorRow, 0, len(registry.List()))
	for _, spec := range registry.List() {
		path, err := exec.LookPath(spec.Binary)
		rows = append(rows, doctorRow{
			Name: spec.Name, Binary: spec.Binary, Found: err == nil, Path: path,
			Consumes: spec.Consumes, Produces: spec.Produces, Risk: spec.Risk,
		})
	}
	return writeJSON(w, rows)
}

func runPlan(w io.Writer) error {
	plan := struct {
		Tools    []recon.ToolSpec      `json:"tools"`
		Payloads []recon.PayloadPolicy `json:"payload_policies"`
	}{
		Tools: recon.DefaultToolRegistry().List(),
		Payloads: recon.DefaultPayloadRouter().List(),
	}
	return writeJSON(w, plan)
}

func runEdge(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("edge", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	from := fs.String("from", "", "producer tool")
	to := fs.String("to", "", "consumer tool")
	if err := fs.Parse(args); err != nil {
		return err
	}
	registry := recon.DefaultToolRegistry()
	producer, err := registry.MustGet(*from)
	if err != nil {
		return err
	}
	consumer, err := registry.MustGet(*to)
	if err != nil {
		return err
	}
	if err := recon.ValidateGraphEdge(producer, consumer); err != nil {
		return err
	}
	return writeJSON(w, map[string]any{"compatible": true, "from": producer.Name, "to": consumer.Name})
}

func runSocket(args []string, in io.Reader, out, errOut io.Writer) error {
	fs := flag.NewFlagSet("socket", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	toolName := fs.String("tool", "", "tool contract name")
	directionRaw := fs.String("direction", "", "input or output")
	var domains stringList
	var cidrs stringList
	fs.Var(&domains, "scope-domain", "authorised domain/FQDN (repeatable)")
	fs.Var(&cidrs, "scope-cidr", "authorised IP/CIDR (repeatable)")
	allowDerived := fs.Bool("allow-derived-ips", false, "permit network probing IPs resolved from in-scope hostnames")
	rejectsPath := fs.String("rejects", "", "quarantine JSONL path")
	source := fs.String("source", "stdin", "source label written to quarantine records")
	maxLine := fs.Int("max-line-bytes", 4<<20, "maximum JSONL record size")
	maxRecords := fs.Int("max-records", 1_000_000, "maximum records in one stream")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *toolName == "" {
		return fmt.Errorf("--tool is required")
	}
	direction := recon.Direction(strings.ToLower(strings.TrimSpace(*directionRaw)))
	if direction != recon.DirectionInput && direction != recon.DirectionOutput {
		return fmt.Errorf("--direction must be input or output")
	}

	registry := recon.DefaultToolRegistry()
	spec, err := registry.MustGet(*toolName)
	if err != nil {
		return err
	}
	scope, err := recon.NewScope(domains, cidrs, *allowDerived)
	if err != nil {
		return err
	}

	var quarantine io.Writer
	var rejectFile *os.File
	if *rejectsPath != "" {
		parent := filepath.Dir(*rejectsPath)
		if parent != "." {
			if err := os.MkdirAll(parent, 0o755); err != nil {
				return fmt.Errorf("create quarantine directory: %w", err)
			}
		}
		rejectFile, err = os.OpenFile(*rejectsPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return fmt.Errorf("open quarantine file: %w", err)
		}
		defer rejectFile.Close()
		quarantine = rejectFile
	}

	socket := recon.NewContractSocket(scope, spec)
	socket.Limits = recon.SocketLimits{MaxLineBytes: *maxLine, MaxRecords: *maxRecords}
	stats, err := socket.FilterJSONL(direction, *source, in, out, quarantine)
	if statsErr := writeJSON(errOut, stats); statsErr != nil && err == nil {
		err = statsErr
	}
	return err
}

func writeJSON(w io.Writer, value any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(value)
}

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return fmt.Errorf("value cannot be blank")
	}
	*s = append(*s, value)
	return nil
}
