# Recon Hound asset pipeline

Typed contracts between stages. Tools are adapters. Anything that fails a
schema goes to quarantine instead of contaminating the next stage.

This is the implementation of the DAG in the project notes and the first
slice of issue #44 / `docs/SAFETY_ROADMAP.md` (verification state, fail-closed
scope, restricted destinations).

See `com.victor.reconloop.contracts`.

Wire-up order:

1. Use `ContractValidator` + `Quarantine` on hosts / URLs / params / findings already in `ReconModel`.
2. Ingest Burp sitemap and proxy history into `hostname[]` / `url[]`.
3. Route `payloads/` through `PayloadRouter` before any corpus probe.
4. Add CLI adapters that emit NDJSON into the same validators.
