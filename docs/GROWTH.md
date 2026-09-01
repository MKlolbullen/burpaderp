# Recon Hound — Growth & Enhancement Plan

Living plan for making Recon Hound a serious bug-bounty control plane without
turning every new pack into an unguarded firehose. Aligns with
[SAFETY_ROADMAP.md](SAFETY_ROADMAP.md), [PIPELINE.md](PIPELINE.md), and issue #44.

## Pillars

1. **Fail-closed ingest.** Every host / IP / URL / finding enters through typed
   contracts (`Asset.*` → `ContractValidator` → `AssetPipeline`). Garbage and
   out-of-scope rows land in Quarantine, not Hosts.
2. **One outbound policy.** No new family is auto-fired until `RequestPolicy` /
   `PlannedRequest` gates every Montoya send (#44 P0).
3. **Hunter-grade corpus, operator-grade fire.** Payload packs can grow ahead of
   the send gateway. Cataloguing a family is not permission to send it.
4. **Evidence that a program will accept.** `VerificationState` on every native
   issue (`SIGNAL` default). Confirmed means reproduced, not "the probe returned
   200".
5. **Local-first.** Burp Java control plane stays authoritative. The Go sidecar
   (`recon/`) is the external-tool data plane, not a second scanner.

## Sequencing

| Slice | Status | Notes |
| --- | --- | --- |
| Typed Java contracts + quarantine ingest | landed on `java-asset-pipeline` (PR #48 → `codex/enhance-burpsuite-plugin`) | `AssetPipeline`, `PayloadRouter`, Quarantine tab |
| Go sidecar contracts | merged via PR #46 | `reconctl`, tool registry, fail-closed adapters |
| Request budgets at send sites | merged via PR #43 | per-probe atomic budget; not yet whole-run |
| Hunter payload packs (SSRF / redirect / CRLF / GraphQL) | this slice | manifest + router labels; **not** in `relevantCategories` |
| `RequestPolicy` send gateway | #44 P0, next | safe methods default; redirect re-scope; metadata/loopback deny |
| Whole-run `ScanRun` + pause/resume | #44 P1 | attach `runId` already stamped on issues |
| Controller split | after policy + ScanRun exist | `ReconController` stays coordinator, not a god-object |
| v1.0 tag | blocked on #44 P0 + evidence migration | do not ship "v1" on corpus size |

## Payload expansion rules

New `.txt` packs under `payloads/` must:

- appear in `payloads/manifest.json` with honest line/byte counts;
- map through `PayloadRouter.fromManifestCategory`;
- stay **out** of `CorpusFuzzEngine.relevantCategories` until the family has a
  policy permission (SSRF/OAST, redirects, CRLF response-splitting, GraphQL
  batching);
- use canaries (`example.com`, loopback, link-local metadata) rather than
  third-party callback infrastructure;
- keep destructive RCE in `rce_payloads.txt`, still gated by
  `PayloadRouter(allowDestructive)` and `isDestructive`.

Current hunter packs beyond the original XSS/SQLi/SSTI/LFI/RCE set:

- `ssrf.txt` — loopback, encoded loopback, cloud metadata, file/dict/gopher,
  k8s/docker local endpoints.
- `redirect.txt` — scheme-relative, backslash, encoding, userinfo, CRLF-tainted Location.
- `crlf.txt` — header injection / response-splitting canaries (`Set-Cookie`,
  `Location`, overlong UTF-8 CRLF).
- `graphql.txt` — typename, introspection, batch, alias amplification, common
  field guesses, persisted-query probe.

`GraphQlFuzzEngine` remains the *active* GraphQL builder. The `.txt` pack is the
corpus twin for opt-in fuzz after policy lands.

## Metrics that matter

Do not score the project on payload-file kilobytes. Track:

- quarantine ratio (rejected / ingested) per run;
- outbound requests per run vs configured budget (must be `<= N`, never `N+1`);
- findings by `VerificationState` (SIGNAL should dominate; CONFIRMED must be rare
  and evidenced);
- time-to-first-in-scope asset from a seed domain;
- false-positive rate on the first five programs you actually hunt.

## Explicit non-goals for this slice

- Auto-firing SSRF/redirect/CRLF/GraphQL from "Run corpus fuzz".
- Shipping a default Collaborator-less OOB payload that hits a third party.
- Replacing Burp Collaborator, logger++, or Autorize.
- Tagging `v1.0.0`.
