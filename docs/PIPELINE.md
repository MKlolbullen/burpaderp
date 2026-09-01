# Recon Hound asset pipeline

Typed contracts between stages. Tools are adapters. Anything that fails a
schema goes to quarantine instead of contaminating the next stage.

This is the implementation of the DAG in the project notes and the first
slice of issue #44 / `docs/SAFETY_ROADMAP.md` (verification state, fail-closed
scope, restricted destinations).

```text
Domains                 domain[]            FQDN + scope + dedupe
   |  subfinder / amass / assetfinder / chaos / findomain / crt.sh / Burp sitemap
Hostnames               hostname[]          FQDN + scope + generation cap
   |  puredns + dnsx
Resolved hosts          resolved_host[]     hostname + A/AAAA/CNAME
   |  alterx / dnsgen / mksub  (generation += 1, cap = 2)
   |
   +--> ip|cidr             canonical, restricted, scanEligible
   |      naabu / masscan   only if scanEligible
   |      service[]         ip + port 1..65535 + tcp|udp
   |
   +--> HTTP input          hostname | service | url
          httpx / Burp
          http_target[]     normalized URL + host + port + status
             |
             +--> katana / gau / cariddi / DiscoveryEngine / webpack / sourcemaps
             |      url[]
             |      arjun / gf / ParameterProfiler
             |      parameterized_url[]
             |      PayloadRouter (family -> compatible consumer)
             |      dalfox / specialized checks
             |
             +--> nuclei / corsy / crlfuzz / ActiveTestEngine
                    finding[]     tool + target + severity + VerificationState
                                  + evidence + runId + detectorVersion
                    report / Burp IssueReporter / notify

All contracts  -. invalid .->  Rejected (schema + reason + raw + source)
```

## Contracts

Java types live in `com.victor.reconloop.contracts`.

| Stage | Type | Reject when |
| --- | --- | --- |
| `domain[]` | `Asset.Domain` | not a FQDN, email, URL, out of scope |
| `hostname[]` | `Asset.Hostname` | invalid labels, wildcard, out of scope, generation > 2 |
| `resolved_host[]` | `Asset.ResolvedHost` | no A/AAAA/CNAME |
| `ip\|cidr` | `Asset.IpOrCidr` | unparseable, out of scope |
| `service[]` | `Asset.Service` | CIDR instead of IP, port 0/65536+, proto not tcp/udp |
| `http_target[]` | `Asset.HttpTarget` | non-http(s), out of scope, status not 1xx–5xx |
| `url[]` | `Asset.Url` | javascript/data/mailto/file, out of scope |
| `parameterized_url[]` | `Asset.ParameterizedUrl` | empty parameter name |
| `finding[]` | `Asset.Finding` | missing tool, evidence, run id, or unknown severity |

`IpOrCidr.scanEligible` is false for loopback, link-local, multicast, RFC1918,
unique-local, and CIDRs wider than `/24` (IPv4) or `/120` (IPv6). Those rows
can still exist as inventory.

URL normalization: lowercase scheme/host, drop default ports, drop fragment,
sort query pairs.

## Payload router

`PayloadRouter` will not attach a family to a parameterized URL whose
`familyHint` is incompatible. RCE is off unless constructed with
`allowDestructive=true`.

`payloads/manifest.json` categories map through
`PayloadRouter.fromManifestCategory`. Profiler labels from
`ParameterProfiler` map through `PayloadRouter.hintFromProfilerClass`.

## Wired into the Burp control plane

- `ReconController.recordAsset` / `recordIp` / `addDiscovered` fail closed through `AssetPipeline`.
- Invalid hosts, IPs and URLs land in `Quarantine` and the Quarantine tab instead of Hosts / Discovered.
- `profileParameters` stamps a payload family from `ParameterProfiler` classes.
- `CorpusFuzzEngine.relevantCategories` keeps universal corpus categories and asks `PayloadRouter` before specialized ones (`lfi`, `rce_payloads`).
- `IssueReporter` annotates every native Burp issue with the current `runId` and `VerificationState` (default `SIGNAL`).
- Reset starts a new run id and clears quarantine.

## What this package does not do yet

- Spawn subfinder/httpx/nuclei. Those stay optional PATH adapters (see the Go sidecar in PR #46).
- Replace `ReconController` with a thin coordinator. That is issue #44 P1.
- Enforce `RequestPolicy` on the wire. That remains issue #44 P0.
