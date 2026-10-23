# Native scan runs

The **Scan runs** tab retains native crawl, active, helper and native recon-chain runs and sidecar
imports. Each run has a UUID, start/end timestamps, status, profile, descriptive scope snapshot,
hierarchical quota limits, metrics, bounded audit records, probe outcomes and finding identities.
Retries carry the parent run UUID. Request and mutation receipts, finding evidence and correlated
callbacks retain their originating run UUID. Passive findings generated while processing a crawl
response also carry that run; unrelated proxy/passive observations have no invented run identity.
Burp's current scope remains authoritative: the saved domain/CIDR snapshot never grants scope.
The snapshot lists intended hosts at run creation, not Burp's full include/exclude configuration;
large snapshots are explicitly marked truncated.

## Controls

Select a live run and use **Pause**, **Resume** or **Cancel**. Pause waits at the next gateway/probe
boundary, before destination preparation/admission, without changing the UUID or refilling quotas.
A request paused after quota reservation rechecks current policy, scope and binding before its dispatch commit; resuming does not acquire a second token. A denial after reservation keeps the token charged. An already committed/in-flight dispatch can finish. Cancel is terminal and wakes paused workers.
Other runs keep their own budgets and state. Cancelling the current crawl clears its pending queue; a later explicitly started crawl keeps the unspent global crawl cap. Disabling active testing, changing any risk grant,
Reset and unload still invalidate old generation tickets; resume cannot revive invalidated work.
The older global crawl Pause/Resume controls retain their session-cancellation semantics and their
unspent global crawl cap. The per-run controls in this tab preserve the current run's ledger.

## Accounting and audit

Every gateway result is recorded, including invalid plans, policy denials, transport errors and
probes that emit no finding. Admission counts remain the hard quota ledger; attempted transport
invocations are recorded before entering Montoya, and response/error counters update on return.
Outstanding dispatch results are visible separately. An admission/cancellation race may consume a
token without a send; tokens are never refunded. A returned HTTP response does not establish probe
success or exploitability. API transport duration does not attest a physical peer or wire RTT.

Request audits contain target identities and exact planned-message SHA-256 hashes, probe ID,
decision code, dispatch state and duration. Bodies, credentials, full URLs and query values are not
copied into history. Finding evidence remains the bounded source for exact HTTP and OOB bytes.
These hashes support correlation, not anonymization against guessing known values.

History retains up to 30 runs, 512 recent events, 256 grouped probe outcomes and 500 finding
identities per run. Totals survive event eviction; explicit omission counters indicate incomplete
detail. Quota detail maps retain 255 keys plus an overflow total. The oldest terminal run is evicted
first; 30 simultaneously live runs cause a new run to be cancelled rather than evicting a live run.
This is bounded project history, not an unlimited or tamper-proof compliance log.

History uses a separate versioned/checksummed JSONL project key. Changes trigger a coalesced save
(250 ms scheduling delay), with periodic and final unload saves. Abrupt process termination can lose
the latest pending save. Unknown, damaged or future snapshots remain byte-for-byte intact until
**Reset state**. Restore starts no HTTP, DNS, Collaborator polling or subprocess, restores no grants,
and never creates a live ScanRun. Previously running/paused/planned records become **INTERRUPTED**; checkpointed unfinished probes become retry-eligible **INCONCLUSIVE** outcomes.
Completed/cancelled/failed status and quota usage are retained. Missing pre-upgrade runs are not
fabricated from old evidence. Late retained callbacks can update their archived run's finding index.

## Compare and retry

Choose a baseline UUID, select another run, and press **Compare**. Identity includes detector and
revision, class, insertion-point label, recorded HTTP method and route/query names, excluding generated payload/OAST tokens,
query values, evidence prose and capture UUIDs. **Show new findings only** filters the Active tests
and Findings tables to added identities in the selected run. Missing observations are labelled
**not observed**, never resolved. Incomplete retained finding indexes make the comparison partial;
unequal targets/profiles/grants/budgets also mean absence cannot establish a fix.

**Re-run failed / inconclusive probes** creates a new child run. Native and corpus probe outcomes
are grouped by original method/URL identity, detector, insertion point/parameter (including location/type) and encoding.
Transport failure, denied/missing observations, truncated native probes, insufficient timing samples, rejected timing response statuses and SIGNAL/CANDIDATE evidence remain retry eligible. Failed local mutation construction is recorded as FAILED without claiming a dispatch;
a skipped prerequisite, checked negative or reproduced/confirmed result alone is not. Corpus retries rebuild the selected
category/parameter/encoding with the original local category cap and current run quota. The corpus
continues to exclude destructive entries. Helpers, external providers and subprocesses are not
silently replayed by this button; use their explicit existing actions.

Retry staging resolves the most recent matching message in the **current** in-scope site map.
Missing/out-of-scope targets are skipped and counted. Current session headers replace historical
credentials; current risk grants, scope, destination validation and quotas are enforced again for
every request. New OAST identifiers are generated. An OAST grant still does not grant persistent
browser payload permission. Queued retries cannot survive disable/re-enable, risk changes or reset.
Historical requests and callback tokens are never replay authorization. Retrying an inconclusive
probe can still repeat a mutating operation when its independent current grants permit it.

## Ownership and validation

`ScanRun` owns lifecycle, quotas and atomic metrics. `RunHistory` owns live lookup, bounded retention,
comparison and retry selection. `RunHistoryCodec` validates durable records. `RunRetry` reconstructs
and executes eligible probes through existing engines/gateway. `RunHistoryPanel` owns the history
UI. ReconController connects these contracts to current Montoya scope, workers, evidence and project
persistence; unrelated controller extraction remains incremental.

`RunHistoryIntegrationTest` and `RunRetryIntegrationTest` cover accounting, pauses/cancellation,
strict snapshot preservation, interruption on restore, stable comparison, refreshed credentials,
current scope and quota checks, queued permission invalidation and restricted corpus retries. The
outbound invariant and evidence migration suites continue to run in CI. Actual Burp peer/egress
verification in `DESTINATION_BINDING_VERIFICATION.md` remains a separate release gate.
