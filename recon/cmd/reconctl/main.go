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
	case "render":
		err = runRender(os.Args[2:], os.Stdin, os.Stdout, os.Stderr)
	case "adapt":
		err = runAdapt(os.Args[2:], os.Stdin, os.Stdout, os.Stderr)
	case "run":
		err = runTool(os.Args[2:], os.Stdin, os.Stdout, os.Stderr)
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

  # normalized Record JSONL -> canonical records
  reconctl socket --tool <name> --direction input|output --scope-domain example.com

  # normalized Record JSONL -> actual stdin lines for the tool
  reconctl render --tool dnsx --scope-domain example.com

  # actual machine-readable/raw tool stdout -> normalized Record JSONL
  reconctl adapt --tool dnsx --scope-domain example.com

  # execute a pinned command profile between both contract sockets
  reconctl run --tool subfinder --scope-domain example.com < domains.jsonl
  reconctl run --tool naabu --scope-cidr 203.0.113.0/24 --allow-network < ips.jsonl
  reconctl run --tool nuclei --scope-domain example.com --allow-active < urls.jsonl

Shared stream flags:
  --scope-domain example.com        repeatable
  --scope-cidr 203.0.113.0/24      repeatable; use /32 or /128 for a single IP
  --run-id UUID                    optional execution ID on records emitted by run
  --allow-derived-ips              explicit override for DNS-derived network targets
  --rejects run/rejects.jsonl      append rejected records with reason/provenance

run additionally requires explicit --allow-network for network_probe tools and
--allow-active for active-fuzz/vulnerability tools. No shell command string is
constructed; pinned argument vectors are executed directly.`)
}

type doctorRow struct {
	Name     string          `json:"name"`
	Binary   string          `json:"binary"`
	Found    bool            `json:"found"`
	Path     string          `json:"path,omitempty"`
	Profiled bool            `json:"profiled"`
	Consumes []recon.Kind    `json:"consumes"`
	Produces []recon.Kind    `json:"produces"`
	Risk     recon.RiskClass `json:"risk"`
}

func runDoctor(w io.Writer) error {
	registry := recon.DefaultToolRegistry()
	rows := make([]doctorRow, 0, len(registry.List()))
	for _, spec := range registry.List() {
		path, err := exec.LookPath(spec.Binary)
		_, profiled := recon.CommandProfileFor(spec.Name)
		rows = append(rows, doctorRow{
			Name: spec.Name, Binary: spec.Binary, Found: err == nil, Path: path, Profiled: profiled,
			Consumes: spec.Consumes, Produces: spec.Produces, Risk: spec.Risk,
		})
	}
	return writeJSON(w, rows)
}

func runPlan(w io.Writer) error {
	plan := struct {
		Tools    []recon.ToolSpec       `json:"tools"`
		Profiles []recon.CommandProfile `json:"command_profiles"`
		Payloads []recon.PayloadPolicy  `json:"payload_policies"`
	}{
		Tools:    recon.DefaultToolRegistry().List(),
		Profiles: recon.ListCommandProfiles(),
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

type contractArgs struct {
	socket      recon.ContractSocket
	direction   recon.Direction
	source      string
	rejectsPath string
}

func parseContractArgs(command string, args []string, withDirection bool) (contractArgs, error) {
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	toolName := fs.String("tool", "", "tool contract name")
	directionRaw := fs.String("direction", "", "input or output")
	var domains stringList
	var cidrs stringList
	fs.Var(&domains, "scope-domain", "authorised domain/FQDN (repeatable)")
	fs.Var(&cidrs, "scope-cidr", "authorised CIDR; use /32 or /128 for one IP (repeatable)")
	allowDerived := fs.Bool("allow-derived-ips", false, "permit network probing IPs resolved from in-scope hostnames")
	rejectsPath := fs.String("rejects", "", "quarantine JSONL path")
	source := fs.String("source", "stdin", "source label written to quarantine records")
	maxLine := fs.Int("max-line-bytes", 4<<20, "maximum line/record size")
	maxRecords := fs.Int("max-records", 1_000_000, "maximum records in one stream")
	if err := fs.Parse(args); err != nil {
		return contractArgs{}, err
	}
	if *toolName == "" {
		return contractArgs{}, fmt.Errorf("--tool is required")
	}

	var direction recon.Direction
	if withDirection {
		direction = recon.Direction(strings.ToLower(strings.TrimSpace(*directionRaw)))
		if direction != recon.DirectionInput && direction != recon.DirectionOutput {
			return contractArgs{}, fmt.Errorf("--direction must be input or output")
		}
	} else if strings.TrimSpace(*directionRaw) != "" {
		return contractArgs{}, fmt.Errorf("--direction is only valid with socket")
	}

	spec, err := recon.DefaultToolRegistry().MustGet(*toolName)
	if err != nil {
		return contractArgs{}, err
	}
	scope, err := recon.NewScope(domains, cidrs, *allowDerived)
	if err != nil {
		return contractArgs{}, err
	}
	socket := recon.NewContractSocket(scope, spec)
	socket.Limits = recon.SocketLimits{MaxLineBytes: *maxLine, MaxRecords: *maxRecords}
	return contractArgs{socket: socket, direction: direction, source: *source, rejectsPath: *rejectsPath}, nil
}

func runSocket(args []string, in io.Reader, out, errOut io.Writer) error {
	cfg, err := parseContractArgs("socket", args, true)
	if err != nil {
		return err
	}
	quarantine, closeFn, err := openQuarantine(cfg.rejectsPath)
	if err != nil {
		return err
	}
	defer closeFn()
	stats, runErr := cfg.socket.FilterJSONL(cfg.direction, cfg.source, in, out, quarantine)
	return finishStream(errOut, stats, runErr)
}

func runRender(args []string, in io.Reader, out, errOut io.Writer) error {
	cfg, err := parseContractArgs("render", args, false)
	if err != nil {
		return err
	}
	quarantine, closeFn, err := openQuarantine(cfg.rejectsPath)
	if err != nil {
		return err
	}
	defer closeFn()
	stats, runErr := recon.RenderJSONLInputs(cfg.socket, cfg.source, in, out, quarantine)
	return finishStream(errOut, stats, runErr)
}

func runAdapt(args []string, in io.Reader, out, errOut io.Writer) error {
	cfg, err := parseContractArgs("adapt", args, false)
	if err != nil {
		return err
	}
	quarantine, closeFn, err := openQuarantine(cfg.rejectsPath)
	if err != nil {
		return err
	}
	defer closeFn()
	stats, runErr := recon.AdaptToolOutput(cfg.socket, cfg.source, in, out, quarantine)
	return finishStream(errOut, stats, runErr)
}

func openQuarantine(path string) (io.Writer, func(), error) {
	if strings.TrimSpace(path) == "" {
		return nil, func() {}, nil
	}
	parent := filepath.Dir(path)
	if parent != "." {
		if err := os.MkdirAll(parent, 0o755); err != nil {
			return nil, func() {}, fmt.Errorf("create quarantine directory: %w", err)
		}
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, func() {}, fmt.Errorf("open quarantine file: %w", err)
	}
	return file, func() { _ = file.Close() }, nil
}

func finishStream(errOut io.Writer, stats recon.SocketStats, runErr error) error {
	if statsErr := writeJSON(errOut, stats); statsErr != nil && runErr == nil {
		return statsErr
	}
	return runErr
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
