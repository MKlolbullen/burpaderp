# Run governance and sidecar handoff

Recon Hound is one product with two deliberately different execution planes:

```mermaid
flowchart TD
    Burp["Burp / Montoya"] --> Policy["ScanRun + request policy"]
    Policy --> Native["Native discovery and probes"]
    Go["reconctl typed sidecar"] --> JSONL["Validated JSONL + run ID"]
    JSONL --> Import["Bounded Burp import"]
    Native --> Issues["Native Burp issues"]
    Import --> Issues
```

- Burp owns captured authentication, target scope, request mutation, Collaborator, evidence markers,
  issue filing, project persistence, and operator decisions.
- `reconctl` owns external binaries, typed streams, adapters, deduplication, process time/size caps,
  and quarantine.

This avoids reimplementing Burp in Go while avoiding shell-pipe orchestration inside the extension.

## Enforcement now

| Boundary | Enforced behavior |
| --- | --- |
| Go process start | `network_probe` and `active_fuzz` are off by default; `--allow-network` / `--allow-active` are explicit. |
| Go tool input/output | `ToolSpec` plus `ContractSocket` validates kinds, schema, scope, size limits, and quarantines rejected JSONL. |
| Go execution identity | `reconctl run` emits a UUID `run_id` on every accepted output record and in its run summary. |
| Burp safe HTTP paths | Discovery crawl/redirects, parameter discovery, JWT read-only replay, and subdomain-takeover checks run through `ScanRun` + `RequestPolicy` + `ActiveRequestGateway`; only in-scope `GET`/`HEAD`/`OPTIONS` requests can dispatch, and each logical run has one atomic request budget. |
| Go → Burp import | The importer bounds line/record count, parses only canonical record kinds, re-checks current Burp scope, and rejects payload/CIDR records that have no safe Burp-side materialisation. Importing never launches a process, adds scope, queues a crawl, or sends traffic. |
| Evidence lifecycle | `SIGNAL`, `CANDIDATE`, `REPRODUCED`, `CONFIRMED`, `EXPLOITABLE`, and `REJECTED` replace a lossy boolean. Legacy `true` maps conservatively to `REPRODUCED`. |

Native target paths now share the gateway. The invariant and its explicit remaining release gates
are described below; external producers are not covered by the native Montoya guarantee.

## Importing sidecar output

Build the sidecar from the `recon/` module, then give each execution either a Burp `ScanRun` UUID or
let `reconctl` generate one:

```bash
cd recon
go build -o reconctl ./cmd/reconctl

printf '%s\n' '{"kind":"domain","value":"example.com"}' \
  | ./reconctl run --tool subfinder --scope-domain example.com \
      --run-id 123e4567-e89b-42d3-a456-426614174000 \
      > subfinder.jsonl
```

In Burp, choose **Import reconctl JSONL…** in the Active testing section and select the output file.
Imported domains, hosts, resolved addresses, services, URLs, parameterized URLs, and findings feed
the existing asset/discovery/parameter tables and the single `IssueReporter` sink. External findings
are filed with `TENTATIVE` confidence until reproduced in the current Burp session.

Rejected import lines are counted and a representative reason is written to the extension output log.
The Go-side quarantine stream remains the authoritative artifact for malformed tool output.

## Native outbound invariant

Every native target-directed Montoya dispatch passes `ActiveRequestGateway`. The controller alone
constructs `MontoyaTargetTransport`; engines receive a caller-owned run and gateway and cannot
create their own authorization or reset the run budget. The transport uses `RedirectionMode.NEVER`.
A crawler redirect is checked against current scope before the discovery auto-add setting is allowed
to observe it, and every followed hop is admitted and charged separately.

The gateway requires a `RequestPlan`, not metadata alone. It binds method/URL and a SHA-256 digest
of `HttpRequest.toByteArray()` to the service host, effective port and TLS flag. The URL and service
destination must agree. Missing inspection data, substituted requests, changed authentication
headers/body, or a changed transport destination fail closed before quota acquisition. Binding is
checked again after policy callbacks/quota acquisition; a change in that interval may conservatively
spend a token but cannot dispatch. This binds the immutable Montoya message at the dispatch boundary,
not bytes after Burp session handling, other extensions, DNS resolution or connection establishment.

The caller owns one run for an active/corpus pass, including its targets, parameters, baselines and
payload categories. The crawler reuses one run across queued URLs and redirects. Pausing cancels that
run; resuming uses only the unspent crawl cap. Reset explicitly starts new accounting. Host/endpoint/
probe reservations are atomic with the global cap, and an explicit default port does not create a
second endpoint quota.

Disabling active tests, changing a risk grant, resetting, or unloading cancels the affected runs.
Enqueue-time generation tickets prevent old jobs from starting again after disable/re-enable,
including jobs already preparing targets but not yet registered. Cancellation does not wait for a
blocking response: a request already admitted may finish, but the next admission fails. A dispatch
that throws is still charged; a cancellation race may conservatively spend a token without a send.
These are Montoya dispatch counts, not a claim to meter internal Burp TCP retries/retransmissions.

Persistent payload permission has no UI grant. Blind-XSS beacons require it as well as OAST and stay
blocked. An OAST grant alone must not silently authorize a potentially stored browser payload.

### Dry-run preview

Every native target-testing/crawl workflow listed below has a **Preview…** action. Previews work with active sending disabled and run
in a background UI worker. They do not enqueue work, register an executing run, send HTTP, allocate
Collaborator payloads, expand scope/site-map inventory, or reserve live quota. The report assumes the
selected workflow will be enabled and shows current risk decisions, all four limits, existing global
usage/remaining capacity, and a bounded candidate scenario. Execution still rechecks every concrete
request through the gateway.

| Action | Request construction / interface | Estimate and conditions |
| --- | --- | --- |
| Parameter discovery | `ParameterDiscoveryEngine.probes` / `plan`: GET baseline and chunks of at most 20 new URL parameters | Upper bound if the baseline returns a response. A denied baseline skips dependent chunks. Added names/counts are shown, captured values hidden. |
| GraphQL introspection / fuzz | `GraphQlRequestPlanner.introspection` / `fuzz` | One introspection candidate or three fuzz candidates (suggestion, 100 aliases, batch), subject to policy/quotas. |
| Active probes | `ActiveTestEngine.plan(base, probeFilter)` | Candidate catalog shares payload constants, `InsertionPoint.apply`, callback/XML/upload builders and permission derivation with execution. Includes baseline/error/boolean/timing branches, NoSQL, traversal, headers, CORS, auth bursts, uploads and XXE. Baseline admission dependencies are explicit; earlier confirmations can skip later candidates. |
| Corpus fuzz | `CorpusFuzzEngine.plan(base, parameter, encodings, maxPerCategory, categoryFilter)` | Shares destructive filtering, raw risk classification, callback rewriting, encoding and parameter mutation with execution. Encodings have stable enum order. Each parameter/category has its own local cap inside the run caps. Timing baselines require two remaining global/local tokens; a denied baseline skips its paired mutation. |
| JWT | `JwtRequestPlanner.plan`, `baseline`, `noneVariants`, `weakSecret` | Original replay, four alg:none variants and an optional offline weak-secret forgery. Forgeries require baseline admission and a successful response. Tokens/claims/signing keys never enter display text. |
| Access-control replay | `AccessControlEngine.plan` | Same cached-response safe-method selection and identity mutation as execution. Cookie/Authorization are removed and configured headers applied; values stay hidden. |
| Takeover | `TakeoverRequestPlanner.plan` / `step` | Stable host ordering, root HTTPS GET, then HTTP fallback unless HTTPS matched a fingerprint. |
| Crawl | `ReconController.previewCrawl(seedText)` / `crawlStep` | Existing queued URLs precede new seed inputs; comments and duplicates are skipped. Uses the same authenticated GET builder and an existing crawl-ledger snapshot or the remaining resume cap. Future redirect targets remain unknown; preview does not follow them or predict future discovery. |

`NativeRequestRecipe` builds a concrete `NativeRequestStep` lazily. Known requests receive the same
byte/service-bound `RequestPlan` required at dispatch. Callback-dependent recipes use an inert
`.invalid` placeholder and **no executable binding**. Unknown redirect destinations are metadata-only
continuations. These are displayed as `PENDING_BINDING` / `PENDING_DESTINATION` when their known
method/literal-destination/permission checks pass, and are excluded from quota simulation. Exact
scope and quota admission wait for the real request. `RequestPolicy.assessTemplate` is a partial
preview assessment; the architecture test forbids execution code and method references from using
it. The gateway always evaluates the full policy.

`RequestPreview.inspect` uses an isolated copy of the existing run ledger and the same gateway
admission routine. For dynamic flows its count describes an **ordered candidate scenario**, not a
worst-case bound: response branches, early matches and runtime values change which requests run.
The configured global run cap remains the hard dispatch ceiling. Preview does not reserve capacity;
concurrent sends or changed settings can change the result. No synthetic responses or fake timing
measurements are used to drive the active engine.

At most 500 candidates are evaluated. Truncated counts describe only that prefix. Probe/category
filters make later groups inspectable; a filtered count covers that selection alone and does not
change what the Run action executes. Original URL paths/query values, header/body values, uploaded
filenames and detector evidence stay out of the display report, including quota-denial reasons.
Generated insertion-point names and variant/encoding identifiers are shown with bounded, control-safe
text. Active/corpus candidate catalogs must be updated with new probe variants; integration tests
compare production transport calls and per-probe cardinality against the catalog across request
surfaces.

### Verification

`OutboundGatewayInvariantTest` resolves Java API owners and catches method references, aliases,
whitespace changes, batch sends and alternate Montoya request engines. It also prevents engines
from calling the raw gateway sender. The fixed-origin crt.sh client is the sole native HTTP exception;
it uses one-hop options too, and its origin/redirect behavior has an integration regression test.

`OutboundRunIntegrationTest`, `ReconControllerRunLifecycleTest`, `RedirectPolicyIntegrationTest` and
`NativeControllerDispatchIntegrationTest`, `CorpusRiskPermissionIntegrationTest` and
`NativeRiskPermissionIntegrationTest` exercise production paths with an in-memory Montoya transport.
They meter actual transport calls, including shared engine budgets and concurrent dispatches, rather
than asserting only on a local integer. Run them with the existing JDK 21 `./gradlew test` task.

`RequestPlanIntegrationTest` checks byte/transport substitution, missing inspection data and changes
during policy evaluation. `RequestPreviewIntegrationTest` compares the shared builders against actual
transport calls, checks each quota dimension against a populated ledger, tests denied prerequisites,
conditional/truncated estimates, redaction, and controller previews with active sending disabled.
`NativeProbePreviewIntegrationTest` compares every dispatch and per-probe count in a no-early-hit pass
against the active catalog across parameters, JSON, path, headers, XML and multipart. It also checks
corpus caps/encoding/timing pairs, pending template isolation, denied dependencies, bounded lazy
construction, and a branch counterexample where a greedy count is smaller than another valid branch.
`NativeControllerPreviewIntegrationTest` covers read-only preview entry points, JWT/identity/takeover
parity, crawler continuation/queue ordering, existing accounting and secret-free display.

### Remaining release gates

This invariant is scoped to native Montoya target traffic. The standalone JDK CLI, external sqlmap,
HTTP-producing Go profiles and PDCP scan creation are separate producers; native request quotas do
not meter their downstream traffic. Their process flags or validated output records are not proof of
a per-request gateway. They need controlled egress or a fail-closed execution boundary before the
product can claim a unified outbound guarantee.

Issue #44 still requires destination validation tied to the actual DNS/connection path and versioned
structured evidence persistence, alongside the external-producer boundary above. Plans here
are in-memory dispatch bindings, not persisted approval artifacts or run audit trails. Do not
interpret passing native tests as closing #44 or approving v1.0.
