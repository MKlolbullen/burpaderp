# Run the Burp destination-binding experiment

Status: **Burp execution NOT RUN** in this workspace. The host has no Burp runtime and cannot create
an isolated network namespace. Local/CI tests exercise production API paths with a fake Montoya API
and test the receiver over real loopback HTTP/TLS sockets. Neither is a Burp wire-level test.

This kit makes an initial set of eight connection-path experiments executable and reviewable.
It does not replace the [full matrix](DESTINATION_BINDING_VERIFICATION.md), control Burp's networking,
or turn observation into outbound enforcement. No result approves v1.0 or closes #44.

## Build and load

Run `./gradlew clean build`. The normal scanner stays in `build/libs/`. The separate manual harness is
`build/runtime-verification/recon-hound-runtime-verification.jar`; it is also included in the CI JAR
artifact. Its only extension entry point is `RuntimeVerificationExtension`. It reuses the unchanged
`ActiveRequestGateway`, `RequestPolicy`, `DestinationGuard`, `MontoyaTargetTransport` and evidence DTOs.
CI checks the entry-point separation and architecture rules cover both source sets.

Use a dedicated Burp test project, with unrelated active extensions/tasks stopped. Load the harness
under Extensions → Installed → Add → Java. The **Recon runtime verification** tab is idle on load:
it registers no HTTP handlers/scanner checks and changes no scope or network/session settings. Do not
load the normal scanner just to run this experiment.

## Prepare an operator-controlled receiver

Use an address and machine you control that production destination classification accepts as public.
Do not use someone else's public address, weaken the guard or pass loopback/documentation ranges as
positive targets. An isolated lab may own its routed addresses, but isolation must be verified outside
the application. The Python receiver can bind private/loopback interfaces for its own tests; the Burp
harness still rejects those addresses as positive target configuration.

On the receiver, allow ingress only from the lab's Burp/proxy hosts. Install Python 3.10+ and a TLS
certificate/key for the logical hostname. For a synthetic lab certificate only:

```bash
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj '/CN=fixture.example.test' -addext 'subjectAltName=DNS:fixture.example.test' \
  -keyout fixture-key.pem -out fixture-cert.pem

python3 tools/runtime-verification/fixture.py \
  --bind "$OWNED_PUBLIC_IP" --http-port 18080 --https-port 18443 \
  --cert fixture-cert.pem --key fixture-key.pem --log fixture-direct.jsonl
```

The new log is created with owner-only permissions and never overwritten. The receiver has no outbound
client, redirect following, DNS lookup or proxying. It records every accepted TCP connection, TLS
handshake/error, SNI, receiving local address/port, exact bounded HTTP request and sent response bytes.
It supports one synthetic GET per connection, HTTP/1.1 only, with `Connection: close`; request bodies,
HTTP/2 and connection reuse/coalescing are explicitly outside this initial fixture. The `/redirect`
response points to `http://127.0.0.1:1/recon-hound-denied` without contacting it.

The certificate is not automatically installed in Burp or a trust store. Record Burp's actual TLS
verification policy separately. Production currently sets SNI but does not call
[`withUpstreamTLSVerification()`](https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/http/RequestOptions.html); a successful handshake does not prove certificate validation. Do not
change production options just to make the experiment pass.

For system resolution, configure the logical name to the controlled public address on the Burp host
(controlled DNS or an explicit OS hosts entry). JVM/OS DNS caching is part of the recorded environment.
The fixture's own hostname is never resolved by the receiver.

## Capture and run

1. Start independent packet capture on the Burp host and actual egress/proxy hop, plus the receiving
   host. Restrict capture to lab addresses/ports where possible. Keep all accepted connections,
   including failures, retries, CONNECT and SOCKS traffic; no HTTP marker alone proves their absence.
2. Save the exact Burp build/edition, OS/JVM, project/user networking and session-rule configuration,
   enabled extensions and certificate policy as protected artifacts. Record capture clocks and
   capture boundaries. Hash the settings/capture files. The profile label below is only an operator
   label; the harness does not attest settings or export credential-bearing configuration.
3. Add both logical fixture origins (HTTP and HTTPS with the chosen ports) to Burp scope manually.
   Paste this configuration into the harness, replacing the address with your owned public address:

```json
{
  "host": "fixture.example.test",
  "address": "REPLACE_WITH_OWNED_PUBLIC_IP",
  "httpPort": 18080,
  "httpsPort": 18443,
  "directResolver": "system",
  "profile": "direct-baseline"
}
```

`system` uses the production bounded resolver for the direct HTTP/HTTPS, redirect and budget cases.
`controlled` injects only the configured public answer for those cases, isolating numeric binding
without exercising system DNS. The protected/mixed/changed-answer cases always use explicitly labeled
injected answers through the unchanged production guard; they are **not** tests of real DNS rebinding
or resolver timing. `address` is the expected receiving address, not a system-DNS pin override.

4. Configure finite Burp response/connection timeouts. Click **Run fixture verification**, then choose
   a new API-report path. Existing files are rejected before any request. The harness writes owner-only
   files on POSIX and checkpoints after each case. Cancellation invalidates the current run and stops
   subsequent cases; it cannot retract an in-flight Burp request. Unload requests cancellation too.
5. Stop capture and the receiver when the run finishes. Preserve the original API JSON, receiver JSONL
   and independent captures/settings with hashes. The report intentionally remains
   `physicalPeerVerification: NOT_RUN` / `releaseDecision: NOT_EVALUATED`.

| Case | Expected API observations | Required independent check |
| --- | --- | --- |
| `http` | One allowed GET/200 | Checked numeric destination and exact request/response bytes at receiver; inspect first TCP peer separately. |
| `https` | One allowed GET/200, logical-host SNI | Receiving address, SNI and bytes; independent certificate-policy and peer review. |
| `redirect` | One GET/302; no automatic follow | No loopback connection from Burp/proxy, including unmarked attempts. This tests Montoya `NEVER`, not the crawler's explicit redirect loop. |
| `protected-answer` | Protected injected answer, zero dispatch/quota | No destination connection; API denial alone is insufficient. |
| `mixed-answers` | Public plus protected injected answer, zero dispatch/quota | Same absence requirement. |
| `changed-answer` | First injected public answer dispatches, second injected loopback answer denied | Only the first request reaches any receiver; not a live DNS-rebinding proof. |
| `budget` | Three attempts in one two-token run; exactly two API dispatches | Count every wire request/connection/retry independently. |
| `cancelled` | Pre-cancelled run denied, zero dispatch/quota | No connection. DNS-in-flight cancellation and revocation remain separate matrix cases. |

The eight cases plan eleven attempts and normally make six Montoya dispatches, all synthetic safe
GETs without credentials/OAST. Receipts retain each case's distinct `ScanRun` ID and experiment/attempt
markers. Raw report bytes are still sensitive if session rules or another extension adds credentials.
Scope revocation and production admission checks remain live before every send.

## Offline comparison

Copy the receiver log alongside the API report, then run locally:

```bash
python3 tools/runtime-verification/reconcile.py \
  --api-report burp-runtime-evidence.json --fixture-log fixture-direct.jsonl \
  --output comparison-direct.json
```

The comparison performs no network I/O. It validates bounded/versioned input, marker/raw-byte
consistency, digests, experiment shape and the eight case protocols. It compares receiving numeric
address/port, Host, SNI, exact requests/responses, missing/extra requests and denied attempts reaching
the fixture. It hashes the original inputs in its new output; existing output is preserved. An orderly fixture-stop marker is required; logs from a still-running
or abruptly terminated receiver are rejected as incomplete.

Exit 0 means the supplied API/receiving observations agree, **not** that peer enforcement passed.
Exit 1 means missing/mismatching/incomplete observations; exit 2 means invalid input or file error.
Denials without marked HTTP observations explicitly keep `connectionAbsence: NOT_VERIFIED`.
Unmarked accepts and TLS failures remain visible in the source logs. The tool cannot turn receiver
logs into proof of Burp's initial peer, absence of other network traffic, TLS trust validation, or a
proxy's downstream DNS behavior. Hashes are integrity references, not authenticity signatures.

Rerun with new file names and explicit profiles for each upstream HTTP proxy, SOCKS mode, host override
and session-rule configuration. Use a second controlled receiver for routing overrides and retain
both logs. Receiving A's empty log is not proof that B was never contacted. A receiving match through
a proxy still requires review of CONNECT/SOCKS address types and the actual intermediate route.

## Complete the release gate

An analyst must populate the full runtime matrix with actual Burp/capture evidence, supported/excluded
configurations and any required controlled-egress change. HTTP/2, two logical hosts on a shared IP,
reuse/coalescing/retries, IPv6 system resolution, live DNS rebinding, in-flight DNS cancellation and
session rewriting still need dedicated runtime cases. This first fixture has deliberate limits; no
global success boolean or operator label can approve the connection path.

CI runs the JUnit production-path/idle-load/configuration tests, real loopback receiver HTTP/TLS tests,
negative offline comparison tests and separate-JAR smoke checks. It does not launch Burp, use external
targets or record a successful Burp matrix row. The verification harness never changes the production
sender, grants, classifier or disabled external target-HTTP features.
