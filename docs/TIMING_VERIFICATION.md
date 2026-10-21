# Timing verification contract

Native SQLi already used repeated median/MAD measurements. Corpus timing previously used one
baseline/payload pair, and both paths measured the whole engine call, including gateway resolution
and client throttle. A missing response could also be counted as a valid elapsed sample. The native
SQLi and corpus detector revisions are now `2` with the following contracts.

## Measurement

`ActiveRequestGateway.Result.transportElapsedNanos` and the corresponding evidence exchange field
measure only the admitted `Sender.send` / prepared `Dispatch.send` invocation with a monotonic clock.
Gateway DNS, admission, plan construction, engine pacing and evidence encoding are outside this
interval. The existing `elapsedNanos` retains its original gateway-total semantics. Both clocks use
`System.nanoTime`; a package-local clock injection permits deterministic tests without real delays.

This remains an API duration. Burp queuing, connection establishment, TLS, internal name/proxy work,
retries and response handling performed inside the invocation remain included. It is not a wire RTT,
server CPU timer or proof of database/interpreter execution. The prepared sender's final binding
check is inside the transport invocation too. Actual connection-path verification remains NOT RUN.

A denied request has transport duration `-1`. An attempted invocation retains its elapsed duration
even if it throws, but a timing sample requires a non-error result, a response object and a completed
2xx/3xx HTTP response. Missing responses, 4xx/5xx responses (including rate limits), failed dispatches,
unavailable status data and unknown legacy durations are excluded. These exclusions are conservative:
a genuine delayed operation that ends in an HTTP error will not be automatically reproduced here.
Other error/body detectors keep their existing response-based behavior.

## Bounded verification

| Path | Measurement sequence | Finding state |
| --- | --- | --- |
| Native SQLi | Existing error/boolean phase; three valid control measurements and three valid payload measurements per tried delay variant. | Existing median/MAD repeated-signal criterion yields REPRODUCED. Incomplete/invalid series do not yield a reproduced timing finding. |
| Corpus timing, each raw payload and selected encoding | Up to three alternating control/payload pairs, each retaining its exact encoded mutation and ordered receipts. | REPRODUCED needs all three valid pairs, the shared median/MAD criterion and at least two matched pair deltas of 4 seconds or more. An isolated/partial/inconsistent pair anomaly is CANDIDATE, never a native reproduced issue. No delayed pair yields no timing finding. |

The expected delay remains the existing five-second detector target. The shared comparator requires
median payload minus control of at least `max(4000ms, 6 × control MAD, 1000ms)` and at least two thirds
of payload samples delayed relative to the control median. Corpus matched pairs provide an additional
check against unrelated controls inflating unpaired medians. Three pairs do not establish a formal
p-value or exploit impact. Raw sample lists, median/MAD, counts and the measurement source appear in
the confidence rationale; nanosecond observations persist with request/response evidence.

Global and local category caps must have two tokens remaining before starting each corpus pair.
Host/endpoint/probe limits, current scope, risk grants and cancellation are still checked on every
actual gateway send. They can stop a pair after its control, as can concurrent exhaustion or a failed
response; this is not an atomic multi-request reservation. Only completed matched pairs enter the
analysis. A later failure may leave an earlier anomaly as a clearly incomplete CANDIDATE.

Failed transport invocations now also spend corpus category quota. Previously the local charge
occurred after the error check, allowing failed requests to bypass the category cap while still
spending global quota. Admission denials consume neither category nor global quota. The category
ledger remains private to a serialized fuzzer invocation; shared run quotas remain atomic.

## Preview and stored evidence

Corpus previews show all six candidate mutations for each timing encoding, with two-token control
requirements, baseline-success payload conditions and chained later pairs. They still perform no
resolution, sending, Collaborator allocation or sample fabrication. Valid no-error execution matches
the simulated quota count; response failure, cancellation and revocation can shorten a conditional
series. Configure at least six remaining local/global tokens to complete one timing encoding, plus
sufficient host/endpoint/probe allowance. No grant or quota is raised automatically.

Evidence schema `2` adds `transportElapsedNanos` as a decimal string (`-1` unknown). Gateway totals
retain their original meaning. The schema-1 migration keeps IDs, raw bytes, detector revision,
historical state and rationale and assigns unknown transport duration. It never derives new samples
from old gateway totals or re-runs stored requests. A checked-in schema-1 fixture tests the migration
and its original digest validation. Future/corrupt snapshots remain protected from automatic writes.

`TimingVerificationTest` covers repeated/partial/outlier/jitter/mismatched controls and invalid sample
sources. `TimingProbeIntegrationTest` drives actual gateway/engine paths with a virtual monotonic
clock: delayed DNS cannot become a payload delay, repeated mutations stay within every quota,
failures spend local quota, invalid responses stay unverified, and scope/cancellation stop subsequent
sends. It also compares all six preview mutations against quota-bounded execution and checks native
SQLi measurements. Existing production-path, runtime-kit, persistence and egress invariant tests stay
in the normal suite. No test sleeps for a five-second simulated payload or contacts an external target.
