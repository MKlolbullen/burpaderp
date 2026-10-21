# Five-agent evidence jobs

The **Agent team → Five-agent evidence jobs** workspace turns selected, redacted evidence into five
bounded review jobs. Each agent has a role, versioned review procedures (“skills”), an allowlist of
local tools and a provider/model binding. These are implemented Java components, not installed
ChatGPT skills or unrestricted remote agents.

| Job | Agent | Default provider | Skills / deliverable | Dependency |
| --- | --- | --- | --- | --- |
| `surface` | Surface analyst | Gemini | Inventory captured endpoints, fields, sources/sinks, trust boundaries and missing context | Selected evidence |
| `poc` | Vulnerability / PoC analyst | OpenAI | XSS, CSRF, SSRF, access control, secrets, injection and logic review; source-grounded candidates with manual PoCs | `surface` |
| `boundaries` | Payload / boundary specialist | Venice | Encoding, parsing, type and origin boundaries; inert payload variations and prerequisites | `poc` |
| `review` | Skeptical reviewer | xAI / Grok | Review every candidate ID, challenge reachability/sanitization/permissions, record counterexamples and missing evidence | `boundaries` |
| `report` | Lead reporter | Anthropic / Claude | Rank hypotheses, review every candidate, retain disagreements and identify next manual checks | `review` |

These provider assignments are editable presets, not rankings of model quality. Models/keys come
from enabled provider rows in **AI analysis**, including the environment variables described in
[AI evidence review](AI_EVIDENCE_REVIEW.md). Five agent instances are always configured, one per
role. Providers can be reused, but the skeptical reviewer must use a different provider from both
the PoC analyst and the payload specialist. A team needs at least two configured providers.

## Use the team

1. Stage captured HTTP exchanges or UTF-8 files in **AI analysis → Evidence review**. Enter an optional
   review focus. Enable the provider rows needed by the five-agent roster and set available model IDs.
2. Click **Plan agent jobs…**, or open **Agent team → Five-agent evidence jobs** and click
   **Preview five-agent jobs**. Configure each role's provider, output-token limit and local-tool limit.
3. Inspect the plan: job dependencies, provider/model recipients, exact role instructions, allowed
   tools, call/output limits, and the frozen redacted source JSON with source hashes.
4. Click **Run previewed jobs**. The job table shows dependency, provider-call and local-tool states.
   The final report includes source-linked candidates, both review verdicts and the local tool trace.

Every listed provider receives the selected evidence. Later jobs additionally receive prior agent
results and redacted local tool outputs. Those derived messages are generated during execution;
the preview explains that data flow rather than claiming to show future messages verbatim. Plan
creation/import/role selection never starts a provider request. Evidence edits, provider/key/model
changes, or roster/budget changes invalidate the plan. Evidence/credential changes also cancel an
ongoing job run. A completed/cancelled run requires a new preview before another dispatch.

## Skills and actual local tools

`AgentSkill` supplies versioned procedures: `surface-v1`, `web-v1`, `access-secrets-v1`, `poc-v1`,
`boundaries-v1`, `skeptic-v1` and `report-v1`. Procedures describe what evidence to inspect and how to
state assumptions; they do not grant execution permission or imply model reasoning parameters.

| Local tool | Actual implementation | Allowed roles |
| --- | --- | --- |
| `source_index` | List selected source IDs, kinds, lengths and SHA-256 hashes | Recon, lead |
| `read_source` | Read a bounded character-offset excerpt from a selected redacted source | All five |
| `search_sources` | Literal case-insensitive search, up to 12 snippets; no regex execution | Recon, analyst, specialist, reviewer |
| `compare_sources` | Length/hash and first differing text excerpt from two captured sources; no behavioral conclusion | Analyst, reviewer |
| `decode_excerpt` | Base64 or URL percent-decode a verbatim selected excerpt into text; preserve literal `+`; mask derived secrets again | Specialist |
| `check_evidence` | Test exact quote presence in a known source, explicitly leaving exploitability unverified | Analyst, specialist, reviewer, lead |

Tools cannot read arbitrary files, access process environment, execute JavaScript/shell commands,
resolve names, fetch URLs, use Montoya HTTP, publish issues or execute PoCs. Source IDs are resolved
only against the immutable snapshot. Unknown/disallowed tool names, extra arguments, wrong types,
invalid offsets, unknown source IDs and non-source decoder input fail the job. Tool requests are
provider-neutral strict JSON, interpreted by the local allowlist; no vendor SDK or remote tool
executor is bundled.

Sources, focus, prior model answers and decoded content remain untrusted data. Prompt injection can
mislead a model's assessment; it cannot add a capability to the local tool registry. Derived tool and
model text is masked again using the existing best-effort redactor before being shared. This still
is not a DLP guarantee: review selected data and the initial preview for custom/encoded secrets.

## Budgets, failures and evidence state

- Default: one local-tool request per agent, so **5–10 provider calls** for a completed run. Each role
  can allow **0–2** local-tool requests, with a hard maximum of **15 provider calls** across the team.
  A tool request consumes one provider response and one local-tool allowance; another provider call
  is needed to produce the final result. A request beyond the allowance fails the job; no retry occurs.
- Output limits are **256–8,192 tokens per provider call**, default 4,096, and are passed into the
  provider request body. The preview calculates the upper bound across all permitted calls. Token
  estimates in reports/feed use text length and are not billed usage or cost guarantees.
- The initial evidence JSON is limited to **120,000 characters**, reserving room for prior results
  and tool text. Derived user messages exceeding **180,000 characters** fail before dispatch instead
  of silently truncating context. Role results are strict JSON, at most **10,000 characters**, with
  up to **5 candidates** each and canonical job history at most **12,000 characters**. Local tool
  output is capped at **4,000 characters**; reads at 3,000 and decoder input at 2,048.
- Each source-grounded candidate gets a stable per-run ID such as `poc:1`. Unknown sources, fabricated
  quotes or invalid finding schemas fail the producing job. Only validated result fields enter later
  job context. Recon, analyst and specialist can propose candidates; reviewer and lead must review
  every candidate ID exactly once and cannot add candidates.
- Review verdicts are **SUPPORTED**, **NEEDS_EVIDENCE** or **REJECTED**. SUPPORTED means a hypothesis
  supported by the selected source, not confirmed exploitability. Reviewer and lead disagreements
  remain visible. All candidate verification states remain **CANDIDATE**, regardless of verdict,
  model confidence or agreement. No native Burp issue is automatically created.
- A failed/incomplete provider response, malformed result, invalid tool request, missing candidate
  review or context/budget failure stops the job; all dependent jobs become **SKIPPED**. The lead
  cannot silently proceed after a missing skeptical review. Run states are COMPLETED, FAILED or
  CANCELLED; COMPLETED is not permission to execute anything and is not a clean bill of health.
- Cancel/extension unloading interrupts the active provider call, and cancellation is checked before
  subsequent jobs, calls and local tools. Already received provider requests cannot be recalled.

Run IDs, prompts, tool traces, model outputs and reports stay in memory. The AI feed records metadata
and estimated token counts for individual provider calls without source snippets or model conclusions.
The existing **Finding inventory (raw input)** workflow remains available as a separate subtab; its
free-text leader election/gate behavior does not grant execution rights to this evidence-job runner.

## Verification and later work

Offline tests exercise five-job ordering, role bindings, skill/tool allowlists, actual source tools,
review coverage, source anchoring, redaction of decoded/model output, call limits, context limits,
cancellation, plan invalidation and UI wiring. Fake-provider integration traverses all five provider
adapters and verifies zero target sends, target DNS lookups, native issue publication or analysis
persistence. Live provider behavior and interactive Burp use still require selected real-world data
and available model IDs.

Parallel job branches, reusable/custom skill editing, durable review history, scheduled background
jobs, provider-native tool schemas, model discovery, billed-usage accounting and guarded promotion
into active verification are later slices. A target verification job would need a separate concrete
request plan and the existing outbound gateway; a model's PoC or SUPPORTED verdict cannot create one.
