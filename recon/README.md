# Recon Hound typed recon sidecar

This directory is the Go data-plane foundation for the external-tool pipeline. The Burp extension stays Java/Montoya: Burp is the control plane, authenticated traffic source, evidence viewer, issue sink, and operator UI. Go is used where it is strongest here: concurrent CLI orchestration, typed streaming contracts, process isolation, normalization, and high-volume de-duplication.

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

`masscan` is intentionally not guessed as line-oriented JSON. Dalfox/Corsy/CRLFuzz output is also quarantined until a machine-stable adapter is declared. **Unsupported output fails closed.**

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

The next step is a small Java/Montoya bridge that starts the Go sidecar for an explicit scan run and imports `finding`/asset events into the existing `IssueReporter` and models. Do **not** move Burp message mutation/evidence markers into Go: the extension already has the right authority boundary for those operations.
