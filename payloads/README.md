# Payload corpus

Raw payload libraries used as an external corpus by Recon Hound.

The extension indexes `.txt` files from the first available directory:

1. `$RECON_HOUND_PAYLOADS`
2. `./payloads`
3. `~/.recon-hound/payloads`
4. `~/payloads`

These payloads are **not automatically fired** by passive scanning, crawling, or the regular active-test pass. The only way to fire this corpus is the opt-in "Run corpus fuzz" button (active tests must already be enabled), which uses `CorpusFuzzEngine`:

- Picks categories per parameter heuristically (universal: `sqli`/`sqli2`/`xss`/`ssti`; `lfi` for path-shaped parameters; `rce_payloads` for parameter names matching `rce.txt`'s hint list, e.g. `cmd`, `exec`, `command`).
- Skips known-destructive entries outright (netcat listeners, Windows account/group/registry/firewall changes, webshell-planting file writes) — these are never fired automatically regardless of settings.
- Rewrites any hardcoded external callback host (`curl`/`wget` to a fixed domain or IP) to this Burp instance's own Collaborator payload instead, so a hit is a real, controlled, confirmable OOB signal rather than a request to a third party's infrastructure. If no Collaborator client is available, that payload is skipped rather than fired at the original host.
- Sends every selected payload in one or more configurable encodings (raw, URL, HTML-entity, Base64, and a few chained combinations) via the panel's encoding checkboxes.

`rce.txt` specifically is **not** a payload list — its lines (`?cmd={payload}`, `?exec={payload}`, ...) are parsed as parameter-name hints for the `rce_payloads` heuristic above, never sent as literal request values.

## Hunter packs (catalogued, not auto-fired)

`ssrf.txt`, `redirect.txt`, `crlf.txt`, and `graphql.txt` are wired through `payloads/manifest.json` and `PayloadRouter.fromManifestCategory` so a parameterized URL can carry the right family hint.

They are **not** returned by `CorpusFuzzEngine.relevantCategories`. That is deliberate: SSRF, open redirect, CRLF, and GraphQL batching/introspection need `RequestPolicy` permissions (issue #44) before they may leave the box. `GraphQlFuzzEngine` remains the active GraphQL builder; the `.txt` pack is the corpus twin for a later opt-in path.

Current categories are described in `manifest.json`. Growth rules live in `docs/GROWTH.md`.
