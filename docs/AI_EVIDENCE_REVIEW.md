# AI evidence review

The existing **AI analysis** tab now opens an **Evidence review** workspace. It reviews captured
HTTP requests/responses, JavaScript/TypeScript, source maps, API specs and other UTF-8 text together.
It makes provider API calls only. It cannot fetch a target URL, run a suggested PoC, execute JavaScript,
follow a model-generated link or file a native Burp issue. Independent review has no tools.
The [five-agent job workflow](FIVE_AGENT_JOBS.md) adds bounded local text tools over the same selected
evidence; open it with **Plan agent jobs…**.

## Configure existing keys

The tracked [`.env.example`](../.env.example) declares empty key/model variables. Copy it to your
own ignored environment file and supply your existing keys locally. The extension does **not** read
dotenv files: export the variables into the process that launches Burp, or use the provider password
fields in the tab. Restart Burp after changing its launch environment. No new keys need to be created.

| Provider | API key variable | Optional model variable |
| --- | --- | --- |
| OpenAI | `OPENAI_API_KEY` | `OPENAI_MODEL` |
| Anthropic / Claude | `ANTHROPIC_API_KEY` | `ANTHROPIC_MODEL` |
| xAI / Grok | `XAI_API_KEY` | `XAI_MODEL` |
| Google Gemini | `GEMINI_API_KEY` | `GEMINI_MODEL` |
| Venice | `VENICE_API_KEY` | `VENICE_MODEL` |

The UI key takes precedence over its environment variable. A blank key field uses the environment;
**Clear entered keys** clears UI fields and invalidates/cancels the evidence review, but cannot unset
the launching process's environment. Model fields initially use the optional environment value,
falling back to the existing built-in defaults. Enter a model ID available to your account; defaults
are convenience values, not an availability guarantee. Models/keys are not persisted by the extension.
Enabling a provider does not send anything. The preview lists the providers/models that will receive
the data; enabled rows without a key are omitted.

## Review workflow

Global scan controls collapse when the AI analysis or Agent team tab opens, leaving room for evidence and results.
Use **Show scan controls** to reopen them; this layout change does not alter scanning permissions.

1. Select one or more captured exchanges in Proxy history, the site map or Repeater, then right-click
   **Recon Hound: AI analysis → Stage exchanges**. Highlighted text can be staged separately.
   These actions only stage local content. No resource is downloaded and no provider is contacted.
2. Add pasted text or import local UTF-8 files. Edit a selected source directly, and optionally enter
   a review focus such as XSS, CSRF, SSRF, secret exposure, access control, injection or business logic.
3. Select providers, keys and models. Click **Preview analysis**. It shows the exact system/user
   message content, recipients/models, redaction count, context size and output-token limit.
4. Review the outbound data, then click **Analyze preview**. Each selected provider receives the
   same frozen evidence snapshot in one request, sequentially. There are no retries or tools.
5. Compare candidate findings, source excerpts, model confidence, assumptions/disproof, suggested
   manual PoCs and remediation. Different providers' findings remain separate; agreement is not proof.

Changing source text, review focus or credentials invalidates a preview. Credential changes cancel an
ongoing review. **Cancel** interrupts the current request and prevents subsequent provider calls;
already received provider requests cannot be recalled. Completed/cancelled reviews require a new
preview before another send. Extension unloading interrupts the owning LLM executor.

## Evidence and data boundaries

- Context is a JSON data envelope with stable session source IDs, source kind/name, redacted source
  text and its SHA-256. Model responses must be strict JSON with at most 20 findings.
- Each accepted candidate references a known source and a verbatim excerpt of its **redacted** text.
  Unknown IDs, invented quotes, invalid enums/types and oversized fields are rejected. Empty findings
  are a valid review outcome; malformed/truncated output is an error, not a clean security result.
- The displayed state is always **CANDIDATE**, even when model confidence is HIGH. An exact match
  establishes only that the excerpt exists; reachability, exploitability and impact remain unverified.
- Automatic redaction masks common credential headers/cookies, sensitive assignments/query values,
  JWTs, private-key blocks and several known key formats. It preserves field names where possible so
  secret-exposure hypotheses can still be reviewed. It is **best effort**, not a DLP guarantee:
  encoded/custom secrets and personal data may remain. Inspect/edit the input and preview before sending.
- Source text/focus are explicitly untrusted prompt data. Prompt-injection instructions do not grant
  tool access: this workflow has no tool execution path, target transport or issue-publishing callback.
  A model can still be misled; source anchoring does not make its conclusions trustworthy.
- Inputs/results/previews live only in memory. The AI feed records provider/model, estimated token
  counts and outcome counts, without copying source text, response text or candidate descriptions.
  Remote provider retention policies still apply to submitted data.

| Limit | Behavior |
| --- | --- |
| 12 sources / 48,000 characters each / 144,000 total | Explicit rejection; edit/remove sources |
| Local file: 256 KiB, valid UTF-8, no NUL | Read at most limit + 1 byte; reject unsupported data |
| Captured exchange | First 23,000 characters per request/response; visible truncation notice |
| JSON user message: 180,000 characters | Reject instead of silently truncating the frozen preview |
| 4,096 output tokens per provider / 120-second request timeout | Truncated provider completions rejected |
| Provider response: 1 MiB | Cancel before buffering more than the limit |
| Results display: approximately 300,000 characters | Visible display cap |

Provider calls stay in `LlmClient`, the existing fixed-origin service exception to the target outbound
gateway. HTTPS origins are fixed, redirects are disabled, credentials are header-only (including
Gemini), and provider error bodies/exception details are not displayed. OpenAI uses Chat Completions
with `max_completion_tokens`; Anthropic uses Messages, Gemini uses `generateContent`, and xAI/Venice
use their existing Chat Completions adapters. Answer parsing follows the assistant response paths,
excludes reasoning/thought parts, and rejects known incomplete/blocked/tool-use finish reasons.

Provider schema references:
[OpenAI](https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create/),
[Anthropic](https://platform.claude.com/docs/en/api/messages/create),
[Gemini](https://ai.google.dev/api/generate-content),
[Gemini authentication](https://ai.google.dev/api),
[Venice](https://docs.venice.ai/api-reference/endpoint/chat/completions).

## Existing tools and follow-up work

**Prompt tools (raw input)** and the existing batch JS/native-issue, chaining, triage, agent-team and
template workflows keep their existing behavior. They do **not** gain the evidence workspace's
redaction/preview/source-anchoring rules. The shared provider transport hardening applies to them.

Provider-native schema enforcement, OpenAI Responses migration, billed-usage/cost accounting,
model discovery, local model endpoints, durable AI review history/export, source-map expansion,
cross-provider deduplication and explicit promotion into the verified evidence pipeline are later
slices. Active verification would require a separate governed request plan through the outbound
gateway; a suggested PoC never grants permission to send it. This does not complete issue #44's
physical Burp connection-path verification or the v1.0 release gate.

Offline tests cover source/file budgets, redaction, exact snapshot anchoring, malformed/empty output,
provider envelopes, bounded response buffering, interrupt propagation, preview invalidation, staged
context-menu selections and integration with the controller. The integration uses fake provider
transports and verifies zero target sends, DNS lookups or issue publication. Live provider requests
and interactive verification inside Burp must be tested separately with your own selected data/models.
