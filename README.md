# Recon Hound — Burp Suite Professional extension (Montoya)

Recon Hound is a scope-bounded asset, attack-surface, and content-intelligence extension for
Burp Suite Professional, written against the **Montoya API** and Java 21.

It is the successor to the original Recon Loop tooling. The earlier tooling was constrained by the
legacy Burp Extender API on **Jython (Python 2)** — end-of-life, no modern language features, awkward
threading, and no access to the current Montoya extension model. This version drops that constraint
entirely: it is a native Java extension with no Python runtime, so it runs on Burp's own JVM with
full access to the modern HTTP handler, site map, scope, scanner-issue, and UI APIs.

## What it does

- Watches in-scope HTTP requests and responses through a Montoya `HttpHandler`.
- Scans request + response content with the Java `RegexHound` port (secrets, tokens, keys, PEM
  material, cloud credentials, provider-specific patterns, JWTs, and more, with entropy gating and
  placeholder suppression).
- Optionally loads normal `gf` JSON packs from `$GF_PATTERNS_DIR` or `~/.gf/*.json` and applies their
  regex patterns.
- Extracts URLs, API endpoints, imports, `fetch()`/Axios calls, source maps, links, forms, and
  interesting file names.
- Recognizes a broad resource set including `.js`, `.ts`, `.webchunk`, `.map`, `.conf`, `.config`,
  `.cfg`, `.env`, `.bak`, `.backup`, `.old`, `.sql`, databases, certificates/keys, archives,
  OpenAPI/GraphQL artifacts, and more.
- Adds discovered resources/directories to Burp scope when enabled.
- Queues deterministic GET requests for discovered file-like resources and endpoints, re-using the
  origin's captured auth headers.
- Follows redirect chains explicitly and scans every hop.
- Profiles Burp-parsed parameters and ranks likely injection/sink classes such as SQLi, XSS, SSTI,
  path traversal/LFI, command injection/RCE, SSRF, open redirect, and IDOR/BOLA.
- Detects response signals such as stack traces, debug disclosures, source-map references, directory
  listings, and internal-hostname hints.
- Indexes external payload `.txt` corpora without blindly auto-firing them.

### Passive XSS surface mapping

Recon Hound maps reflected cross-site-scripting surface passively, using techniques distilled from
the PortSwigger XSS cheat sheet:

- **Reflection-context detection** — for every in-scope response whose request carried parameters,
  the extension looks for parameter values echoed verbatim into the body and classifies the
  reflection *context*: HTML element text, single/double-quoted or unquoted attribute, URL attribute
  (`href`/`src`/`action`…), inline `<script>` string or code block, template literal, `<style>`
  block, HTML comment, or RCDATA (`<title>`/`<textarea>`).
- **Surviving-character analysis** — it reports which XSS-relevant metacharacters
  (`< > " ' ` ( ) { } ; = /`) reached the response unencoded at the reflection point, which is what
  decides whether a given class of vector is viable.
- **Context-aware vector suggestions** — `XssVectorLibrary` holds a curated, categorised set of
  cheat-sheet vectors (tag-injection, attribute breakout, `javascript:`/`data:` protocol tricks,
  JavaScript-string breakout, WAF-bypass global-object concatenation, comment-syntax and hex-escape
  obfuscation, UTF-7 / overlong-UTF-8 / HTML-entity encoding bypasses). For each observed reflection
  it surfaces only the vectors whose required characters actually survived.

The results appear in two dedicated tabs — **XSS reflections** (live, per observed sink) and
**XSS vector library** (the full catalogue as a copy-paste reference). High/medium-confidence
reflections are also raised as tentative Burp audit issues.

This mapping is **passive**: Recon Hound observes only the values the target already returned and
never injects payloads on its own. Confirming XSS still means manually firing a context-appropriate
vector against an authorised target.

## Safety / scope controls

Active discovery is:

- Burp-scope bounded.
- Same-origin by default.
- GET-only.
- Deduplicated.
- Request capped.
- Redirect capped.

Payload execution and XSS vector firing are deliberately separate from discovery. Some corpora
contain time-based, OOB, or destructive strings and should only be launched deliberately against
authorized targets.

## Build

Requires Java 21 and Gradle:

```bash
gradle clean jar
```

The build targets:

```text
net.portswigger.burp.extensions:montoya-api:2026.7
```

Load the generated JAR (`build/libs/burp-recon-hound-0.2.0.jar`) through:

```text
Burp Suite → Extensions → Installed → Add → Java
```

## Payloads

The bundled `payloads/` directory contains the supplied XSS, SQLi, SSTI, LFI, and RCE corpora. At
runtime the extension looks for payloads in:

```text
$RECON_HOUND_PAYLOADS
./payloads
~/.recon-hound/payloads
~/payloads
```

## gf patterns

Normal gf-json files are discovered from:

```text
$GF_PATTERNS_DIR
~/.gf/*.json
```

The lightweight loader supports both a single `"pattern"` and an array of `"patterns"`, plus
case-insensitive `flags` containing `i`.

## Project layout

```text
src/main/java/com/victor/reconloop/
├── ReconLoopExtension.java       # BurpExtension entry point
├── ReconController.java          # HttpHandler + discovery/scan orchestration
├── ReconPanel.java               # Suite tab UI
├── ReconModel.java               # Swing table models
├── DiscoveryEngine.java          # URL/endpoint/source-map extraction
├── InterestingResourceCatalog.java
├── ParameterProfiler.java        # injection-class ranking of parameters
├── ResponseSignalEngine.java     # stack traces, debug/error disclosure, etc.
├── GfPatternLoader.java          # ~/.gf/*.json pattern packs
├── PayloadLibrary.java           # external payload corpus indexing
├── RegexHound.java               # secret/credential regex engine
├── XssReflectionEngine.java      # passive reflected-XSS context mapper
└── XssVectorLibrary.java         # curated, context-aware XSS vector catalogue

payloads/
├── manifest.json
├── lfi.txt
├── rce.txt
├── rce_payloads.txt
├── sqli.txt
├── sqli2.txt
├── ssti.txt
└── xss.txt
```
