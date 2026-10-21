# Versioned active finding evidence

This implements bounded finding evidence for issue #44. It does not close the issue or establish
wire-level destination enforcement. The [Burp runtime matrix](DESTINATION_BINDING_VERIFICATION.md)
remains **NOT RUN**. Gateway receipts describe Montoya API observations; one API dispatch is not a
claim about TCP attempts, delivery, physical peer, browser execution or exploit impact.

## Storage and interfaces

| Owner | Contract |
| --- | --- |
| `ActiveRequestGateway.Result.exchange` | Immutable receipt for an inspected request: run/probe IDs, method/logical URL, policy decision, dispatch-attempt flag, elapsed nanoseconds, exception class, intended request and returned request/response bytes. Denials do not manufacture responses or consume quota. Elapsed time includes preparation/admission, not just the HTTP exchange. Capturing optional evidence cannot change the send result. |
| `EvidenceCapture` | One native probe/insertion point or corpus encoding variant. Captures the original request and ordered receipts; retains real `HttpRequestResponse` objects only for immediate native issue attachment. No replay or approval capability. |
| `FindingEvidence` | Stable evidence ID, capture ID, run ID, source, detector ID/version, typed `VerificationState`, UTC observation time, rationale, reproduction guidance, bounded byte observations, omission counts, issued OAST payload IDs and associated OOB records. Original cached response is included where the comparison uses it, notably access control. Detector version `1` is an explicit implementation revision, not the schema or repository version; bump it when the detector's semantics change. |
| `ActiveEvidenceCodec` | Schema `1` JSONL snapshot: version/count/SHA-256 header, then one JSON object per active table row. Bytes use Base64, full length/hash, captured-prefix hash and capture status. Strict fields/types/enums, run consistency, IDs, timestamp syntax, counts, canonical Base64 and captured hashes are checked before writes and restores. The digest detects accidental changes; it is not an authenticity signature. |
| `PersistedState` | Separate project extension-data string `reconhound.active-evidence`. Encodes before one `setString` replacement. Existing Findings/Hosts/assets/hashed-dedupe keys and AI triage format remain compatible. The snapshot is not a transaction across all those keys or a crash-proof write-ahead log. |
| `ReconController` | Snapshots table references on the EDT; periodic serialization/writes run on the existing background executor. A generation and monotonic snapshot sequence reject pre-reset or superseded saves. Unload performs a final synchronous save. Restore only restores data/deduplication; it starts no run, HTTP, DNS, Collaborator client, poll or issue re-filing. |
| `ReconPanel` | Active tests has independent Observation, Verification and Capture columns. “View evidence…” shows read-only provenance and JSON/Base64 using plain text, including partial-capture flags. There is no replay control. |

The first schema covers findings, not every admitted/denied request in an entire run. Requests from
probes without a finding are not durably journaled, except pending OAST cases retained for callbacks.
Restored records confer no scope/risk grants and do not restore a live run, session or OAST client.
Reproduction needs current authorization, credentials and fresh callback identifiers. Shared corpus
variants can be associated with one payload and remain explicitly ambiguous.

## Coverage and interpretation

| Production path | Retained evidence / interpretation |
| --- | --- |
| `ActiveTestEngine` | Per-probe, per-insertion-point original and gateway sequence, including available baseline/control/mutation responses. Existing typed detector states remain; runtime HTTP evidence is attached to reportable native issues. |
| `CorpusFuzzEngine` | Exact encoded request actually submitted, not just the source corpus string. Timing cases keep baseline and mutation together. An attempted OAST mutation creates a pending SIGNAL case even when there is no response/reflection. |
| Parameter discovery | Baseline plus candidate request; reflected generated canary is REPRODUCED discovery, a lone status/length change is CANDIDATE. This is not vulnerability confirmation. |
| JWT none / weak-secret replay | Valid-token baseline and forged request/response; response acceptance is REPRODUCED, rejection is REJECTED. Status/length similarity does not prove privileged access. |
| Access-control comparison | Original cached request/response plus replay receipt. Matching content is REPRODUCED, partial similarity is CANDIDATE, denied/different results are REJECTED. Actual sensitive privileges need analyst verification. |
| GraphQL introspection / suggestions / aliases / batching | Query and response, typed reproduction of the observed feature. Schema-name heuristics remain candidate interpretations; sensitive-operation or rate-limit impact is not inferred. |
| Takeover fingerprint | Fetched response and CANDIDATE classification. DNS ownership/resource claimability are not established. Existing tentative native “potential” reporting remains. |
| Other passive / LLM / imported rows in Active tests | Explicit METADATA_ONLY, unknown detector version/run and SIGNAL. Observation prose such as “confirmed” never upgrades the typed state. Migrating these detectors and all native passive issue payloads is separate work. |

Native issue details for migrated active paths include evidence ID, detector/version, typed state,
rationale, reproduction guidance and completeness. Available live HTTP evidence is attached when
filing; restore does not reconstruct Montoya objects or re-file an issue. Existing passive Findings
exports (SARIF/Markdown) do not automatically export this raw evidence snapshot.

## OOB association

Native/corpus payload custom data is `AC2|<opaque capture UUID>`; it no longer embeds a target URL or
parameter value. Payload IDs, their test/parameter context and whether their mutation reached the API
dispatch attempt are retained locally. Baseline-only activity cannot authorize callback association.

`OobEvidence` keeps the SDK payload ID, type, timestamp, client address/port, custom data and available
DNS query bytes/type, HTTP protocol/request/response bytes or SMTP protocol/transcript. SMTP is UTF-8
of the SDK conversation string, not an asserted wire capture. A fingerprint includes this metadata
and hashes, allowing distinct timestamps/bodies to remain distinct. Identical observations with no
SDK event identifier cannot be distinguished further.

A callback is CONFIRMED **as an interaction** only if retained capture and dispatched payload IDs
match a known run. Missing, mismatched, unsent or legacy `AC|...` provenance stays CANDIDATE with no
invented target URL (in particular no callback-client-IP fallback). Conflicting run associations fail
closed. Parent evidence IDs and unique packets are retained. The stable callback evidence ID can
upgrade an earlier unlinked row after a parent arrives; confirmed fingerprints survive reload and
prevent duplicate filing. Missing parents after retention eviction cannot be recovered or guessed.

## Bounds, corruption and migration

- At most 64 KiB per message. A larger message keeps its prefix, original length, full SHA-256 and
  prefix hash, marked PREFIX. Missing observations are UNAVAILABLE; removed bytes are OMITTED. Neither
  is presented as complete. Digests cannot reconstruct omitted bytes.
- At most 16 exchanges and 512 KiB of retained Base64 characters per case, with attempted/omitted
  exchange counts. Excess bodies are omitted while their lengths/digests remain.
- Latest 500 rows and 16 MiB of retained Base64 characters in the active table. Oldest rows are
  evicted; older retained cases lose bodies first when the byte bound is reached. This is not a full
  engagement archive. Native Burp issues have their own retention outside this bound.
- Snapshot limit is 24 Mi characters and each record 2 Mi characters, with bounded collections and
  metadata fields. Strict JSON has depth/node limits. An oversized/unserializable new snapshot logs
  a save failure and leaves the previous active snapshot untouched.
- A missing/empty key restores no active history: earlier releases did **not** persist Active tests.
  The compatibility import format (`schemaVersion: 0`, count header, six row strings and optional
  boolean `confirmed`) maps true to REPRODUCED and false/missing to SIGNAL. It invents no prior raw
  bytes, timestamp, run or detector version; a normal save migrates it to schema 1. Legacy constructor
  compatibility uses the same conservative boolean interpretation.
- Future schema versions and malformed/truncated/digest-invalid snapshots restore no active rows and
  are preserved byte-for-byte. Periodic saves and unload cannot overwrite them. Explicit project
  Reset clears the active key into an empty schema-1 snapshot. Existing passive/triage data can still
  restore/save independently.

Raw request/response/OOB data can contain credentials, tokens and personal data. Base64 is not
encryption or redaction. It stays in Burp project extension data and the local read-only viewer;
there is no automatic provider upload or file export in this slice. Protect the project as sensitive
evidence. Reset clears this extension snapshot, not native issues, project backups or exported data.

## Verification and remaining work

`ActiveEvidenceCodecTest` covers every state, binary/newline round trips, stable IDs and large integer
durations, conservative migration, unknown/corrupt/truncated data, envelope-independent validation,
explicit prefix/omission handling, retention and strict JSON. `NativeEvidenceIntegrationTest` uses
actual production engine/controller paths with in-memory Montoya to compare raw observations,
denied/failed attempts, per-probe isolation, encoded corpus/OAST, bounded sequences, helper evidence,
unload/reload without traffic, stale-save ordering and reset during an in-flight response.
`OobEvidenceTest` covers DNS/HTTP/SMTP observations, exact association requirements, ambiguous variants,
callback distinctions, late association and deduplication after restore. All existing transport,
quota, preview, lifecycle and external-egress architecture tests remain in the normal suite.

Before v1.0, complete actual Burp connection-path verification/control and review the remaining #44
contracts against supported configurations. Durable full-run audit/approval artifacts, complete
passive evidence migration, evidence export/redaction, archival/retention controls and restoring
disabled external HTTP producers are separate slices. Finding persistence does not establish those
contracts or permit the disabled producers to execute.
