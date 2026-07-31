# Recon Hound safety and architecture roadmap

Recon Hound now spans passive discovery, active probes, external tools, OAST, LLM analysis, persistence, reporting, and a standalone scanner. The next development phase should prioritise request accountability and evidence quality before adding more detector classes.

## P0: Request policy and hard budgets

Introduce one mandatory outbound-request gate used by every active probe and integration.

```java
interface RequestPolicy {
    Decision evaluate(PlannedRequest request, RunContext run);
}

record Decision(boolean allowed, RiskClass risk, String reason) {}
```

Required controls:

- Safe HTTP methods only by default.
- Explicit per-run permission for POST, PUT, PATCH, and DELETE replay.
- Separate permission for persistent payloads, authentication/lockout probes, uploads, OAST, and time-delay payloads.
- Atomic request acquisition immediately before every network send.
- Global, per-host, per-endpoint, and per-probe request limits.
- Redirect scope validation at every hop.
- Private, loopback, link-local, and cloud-metadata destination controls.
- Cooperative cancellation checked before each request.
- A dry-run view showing planned mutations before traffic is sent.

The budget must be enforced at the lowest outbound layer. A probe must not enter a multi-payload loop based on a stale budget value and then overshoot it.

## P0: Evidence lifecycle

Replace `confirmed: boolean` with an explicit lifecycle:

```java
enum VerificationState {
    SIGNAL,
    CANDIDATE,
    REPRODUCED,
    CONFIRMED,
    EXPLOITABLE,
    REJECTED
}
```

Examples:

- Six requests without a rate-limit response are `SIGNAL`, not `CONFIRMED`.
- A reflected value is `CANDIDATE`; executable browser behaviour is `CONFIRMED`.
- An accepted upload is `SIGNAL`; retrievable dangerous content is `REPRODUCED`; server-side execution is `CONFIRMED`.
- One delayed SQLi request is `CANDIDATE`; repeated statistically significant delays are `REPRODUCED`.

Every finding should retain its detector version, request mutation, response evidence, confidence rationale, and reproduction recipe.

## P1: First-class scan runs

Create a durable run model:

```java
record ScanRun(
    UUID id,
    Instant startedAt,
    ScanProfile profile,
    ScopeSnapshot scope,
    RunStatus status,
    RunMetrics metrics
) {}
```

Every request, mutation, callback, and finding should carry a run ID. This enables:

- New-findings-only comparison.
- Reliable pause, resume, and cancellation.
- Per-run request accounting.
- Historical coverage and run diffs.
- Re-running only failed or inconclusive probes.
- A precise audit trail of what the extension sent.

## P1: Split orchestration from detection

`ReconController` should become a thin coordinator rather than owning crawling, probes, persistence, external integrations, Swing updates, reporting, and scope manipulation.

Suggested boundaries:

```text
core/          Finding, Evidence, Target, ScanRun, Fingerprint
policy/        ScopePolicy, RequestPolicy, DataHandlingPolicy
passive/       PassivePipeline and detector implementations
active/        ActiveRunCoordinator, RequestBudget, probe implementations
discovery/     DiscoveryCoordinator and asset graph
integrations/  LLM, Nuclei, PDCP, sqlmap, OAST
persistence/   repositories and state migration
burp/          Montoya adapters and issue sink
ui/            Swing views and view models
```

Suggested contracts:

```java
interface PassiveDetector {
    String id();
    Stream<Finding> analyze(Exchange exchange, AnalysisContext context);
}

interface ActiveProbe {
    String id();
    ProbePlan plan(Target target, ProbeContext context);
    ProbeResult execute(ProbePlan plan, ProbeRuntime runtime);
}
```

## P1: Response comparison quality

Create a reusable comparison service that can normalise volatile response data before access-control, boolean-SQLi, and other differential tests.

Normalisation should support:

- Status and redirect comparison.
- Selected header comparison.
- JSON canonicalisation with configurable ignored fields.
- HTML/text token similarity.
- Removal of timestamps, request IDs, CSRF tokens, rotating advertisements, and other volatile values.
- Median and median-absolute-deviation timing analysis for time-based probes.

## P2: Identity matrix

Expand alternate-identity replay into named identities and endpoint-by-role results.

```text
Endpoint                  Anonymous   User A   User B   Admin
GET /api/users/123        401         200      200?     200
DELETE /api/users/123     401         403      403      204
```

Support login/session refresh, CSRF extraction, object-ID substitution, request sequences, horizontal versus vertical classification, and field-level response differences.

## P2: Deterministic attack graph

Represent relationships between assets, endpoints, parameters, credentials, identities, findings, and verified chains. Deterministic graph edges should be created before LLM-assisted ranking or explanation.

Example edges:

- Source map -> hidden endpoint -> IDOR candidate.
- Open redirect -> OAuth callback candidate.
- Exposed API key -> authenticated endpoint set.
- SSRF -> internal host -> metadata credential candidate.
- Weak JWT secret -> forged role -> privileged endpoint.

## P2: Schema-driven APIs

Build on existing OpenAPI and GraphQL ingestion with:

- Request generation from schemas.
- Required/optional field permutations.
- State-changing operation classification.
- Identifier extraction from earlier responses.
- Mass-assignment mutation planning.
- Resolver-level authorization matrices.
- Query-cost and alias-cost analysis.
- WebSocket, GraphQL subscription, gRPC, and protobuf support.

## P2: JavaScript analysis

Move important client-side detections from statement co-occurrence toward parsing and lightweight data flow:

- JavaScript/TypeScript AST parsing.
- Scope and symbol tracking.
- Assignments, returns, callbacks, and simple interprocedural flows.
- Webpack module/export reconstruction.
- `postMessage` origin validation.
- URL/hash/storage/message sources into DOM, navigation, network, eval, and template sinks.
- Prototype-pollution and unsafe merge paths.

Use LLMs to explain complex candidate paths, not as a replacement for deterministic parsing.

## P2: Headless scanner v2

Add declarative configuration, response-size limits, proxy and cookie support, environment-backed headers, retry policy, JSONL events, baseline SARIF comparison, and `--fail-on-new`.

## CI and release engineering

Recommended additions:

- Stable releases from version tags; snapshot artifacts from `main`.
- JaCoCo coverage thresholds.
- Static analysis and nullness checks.
- CodeQL and dependency review.
- SBOM generation and artifact attestations.
- Reproducible-build verification.
- Integration tests against a local deliberately vulnerable fixture.
- CLI smoke tests.
- Supported Montoya/Burp compatibility documentation.

## Recommended release sequence

1. **Safety:** request policy, hard budgets, evidence states, secret-safe persistence, cancellation.
2. **Architecture:** scan runs, unified findings/evidence, detector/probe interfaces, versioned persistence.
3. **Verification:** robust response comparison, repeated timing analysis, integration fixtures.
4. **Experience:** run dashboard, dry-run planner, identity matrix, attack graph.
5. **Expansion:** AST JavaScript analysis, schema-driven API tests, durable OAST, headless scanner v2.
