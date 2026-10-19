# Recon Hound typed recon sidecar

This directory is the Go data-plane foundation for the external-tool pipeline. The Burp extension stays Java/Montoya: Burp is the control plane, authenticated traffic source, evidence viewer, issue sink, and operator UI. Go is used where it is strongest here: concurrent CLI orchestration, typed streaming contracts, process lifetime management, normalization, and high-volume de-duplication.

The important design rule is **tools do not pipe arbitrary strings directly into other tools**. Every boundary is:

```text
tool output -> adapter -> typed Record -> scope/schema contract -> dedupe -> next tool input contract
                                  \
                                   -> quarantine JSONL on failure
```

## Contracts

`Record.Kind` is one of:

- `domain`
- `hostname`
- `resolved_host` (`hostname + A/AAAA/CNAME`)
- `ip` / `cidr`
- `service` (`ip/host + port + protocol`)
- `http_target` (`normalized URL + status + host/port`)
- `url`
- `parameterized_url`
- `payload`
- `finding`

`ToolRegistry` declares exactly which kinds each external tool may consume and produce. `ContractSocket` enforces that declaration in both directions, canonicalizes the data, applies scope policy, bounds record/line sizes, and writes failures to a quarantine stream with the tool, direction, source, raw record, and reason.

## The network-scope rule

**A domain being in scope does not automatically make every IP it resolves to safe for network scanning.** Shared hosting, anycast, reverse proxies, and CDNs make that assumption wrong.

The `resolved_host -> ip` transform therefore marks addresses `derived=true`. `naabu` and `masscan` accept only `ip|cidr`; the scope contract then requires either:

1. an explicitly authorised IP/CIDR, or
2. the deliberate `allow-derived-ips` override plus provenance linking the address to an in-scope hostname.

HTTP probing preferentially keeps the hostname instead of substituting the IP, preserving Host/SNI semantics.

## Payload router

`router.go` formalizes the existing `payloads/` semantics. In particular:

- `rce.txt` is `role=parameter_hint`; it cannot be fired as a payload corpus.
- `rce_payloads.txt` is a payload family and requires destructive-payload filtering plus controlled OAST callback rewriting.
- payloads may only route to a `parameterized_url` target — an explicit injection-point contract.

This complements the existing Java `CorpusFuzzEngine`; it does not remove its hard request budgets, destructive filters, or Collaborator rewrite logic.

## Tool adapters implemented

`adapters.go` has real normalization paths for:

- hostname-line / simple JSON outputs: subfinder, amass, assetfinder, chaos, findomain, puredns, alterx, dnsgen, mksub
- `dnsx` JSONL -> `resolved_host`
- `naabu` JSONL -> `service`
- `httpx` JSONL -> `http_target`
- katana / gau / cariddi URL output -> `url`
- `gf` parameterized URLs -> one `parameterized_url` per query parameter
- Arjun JSON document -> `parameterized_url[]`
- Nuclei JSONL -> bounded `finding`
- `trufflehog` `--json` JSONL -> bounded `finding` (verified secrets escalate to `high`)
- `gitleaks` JSON report (array document) -> bounded `finding[]` via `ParseGitleaksReport`

`masscan` is intentionally not guessed as line-oriented JSON. Dalfox/Corsy/CRLFuzz output is also quarantined until a machine-stable adapter is declared, as is the human-readable or file-only output of XSStrike, XSRFProbe, SSRFire, scan4secrets and postleaks (see below). **Unsupported output fails closed.**

## Web vulnerability + secret-exposure tools

The catalog models several additional weakness-finding tools so a multi-tool run
can cover XSS, CSRF, SSRF and secret exposure in the same typed stream — without
piping raw strings between processes.

| Tool | Consumes | Produces | Risk | Output status |
| --- | --- | --- | --- | --- |
| `xsstrike` | `parameterized_url` | `finding` | `active_fuzz` | fail-closed (human stdout only) |
| `xsrfprobe` | `http_target`/`url` | `finding` | `active_fuzz` | fail-closed (writes a report tree) |
| `ssrfire` | `domain` | `finding` | `active_fuzz` | fail-closed (needs an OAST server; writes `output/<domain>/`) |
| `scan4secrets` | `http_target`/`url` | `finding` | `active_fuzz` | fail-closed (JSON/JSONL written to a report file) |
| `postleaks` | `domain` | `finding` | `passive_osint` | fail-closed (JSON written to an output folder) |
| `gitleaks` | source (not modeled) | `finding` | `passive_osint` | **adapter implemented** (`ParseGitleaksReport`) |
| `trufflehog` | source (not modeled) | `finding` | `passive_osint` | **adapter implemented** (`--json` JSONL) |

Like `dalfox`, the XSS specialist `xsstrike` only accepts an explicit
`parameterized_url` injection point, never a bare `url`, and active web
scanners remain blocked until both a pinned adapter and governed target egress exist.
`--allow-active` alone never enables them. Registering a tool with a
fail-closed adapter is deliberate: it pins the typed contract (what may cross the
boundary) now, while the version-specific output parser is added later. No
executable `CommandProfile` is declared for these tools, so `reconctl run` will
not launch them until a pinned invocation + adapter pair exists; their contracts
are still enforced by `reconctl plan`/`edge` and by the `adapt` boundary.

### postleaks -> gitleaks / trufflehog

`postleaks` searches Postman's public library for a keyword/domain and writes the
matching request bodies to an output folder. That folder is exactly the kind of
filesystem source `gitleaks` and `trufflehog` are built to scan, so the intended
flow is:

```text
postleaks -k example.com --output pml/   # dump candidate Postman requests
gitleaks   dir pml/ --report-format json   -> ParseGitleaksReport -> finding[]
trufflehog filesystem pml/ --json          -> trufflehog adapter  -> finding[]
```

Because the *source* consumed by these secret scanners (a git repo, a filesystem
tree, a Postman export) is not yet a pipeline `Kind`, execution is not wired, but
their report output already normalizes into the same bounded `finding` records
every other stage emits — so a Java/Montoya bridge or `reconctl adapt` can import
them directly.

## `reconctl`

Build/test:

```bash
cd recon
go test ./...
go vet ./...
go build ./cmd/reconctl
```

Inspect the declared graph and installed binaries:

```bash
./reconctl plan
./reconctl doctor
./reconctl edge --from httpx --to katana
```

Validate a normalized stream before feeding a tool:

```bash
cat hosts.jsonl | ./reconctl socket \
  --tool dnsx \
  --direction input \
  --scope-domain example.com \
  --rejects run/rejects.jsonl
```

Validate normalized tool output:

```bash
cat dnsx.records.jsonl | ./reconctl socket \
  --tool dnsx \
  --direction output \
  --scope-domain example.com \
  --rejects run/rejects.jsonl
```

`socket` deliberately does not execute the tool. Execution, output parsing, and contract validation are separate layers so one bad parser or process cannot bypass scope policy by accident.

## Next integration boundary

The Java/Montoya JSONL importer already feeds validated asset/finding events into the existing models and `IssueReporter` without starting tools. A future execution bridge must preserve the egress restrictions below and attach the explicit scan run. Burp message mutation and evidence markers remain in the extension.

## Target HTTP execution is paused (#44)

`httpx`, `katana` and `nuclei` retain pinned command descriptions and output adapters, but cannot
execute through `run`, even with `--allow-active` or all `RunPolicy` fields enabled. Both `RunProfile`
and the private process-start boundary reject canonical unsupported egress before any binary starts.
Unknown/unprofiled tools are blocked too. `doctor` reports the execution block; `plan` includes egress
classes. Existing `adapt`, `socket`, `render` and Burp JSONL import stay available without execution.

Provider-only `subfinder`/`gau`, DNS `puredns`/`dnsx`, and explicitly opted-in TCP `naabu` profiles remain
available. Their installed binaries and pinned invocation semantics are trusted; this is not a network
sandbox and their traffic is not charged to a native HTTP run. Restoring target-HTTP profiles requires
an enforceable per-request egress adapter covering scope, redirects, quotas, permissions and
cancellation, rather than additional process flags. See [run governance](../docs/RUN_GOVERNANCE.md).
