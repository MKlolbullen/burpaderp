# Curated GF detection

The versioned catalog contains **167 rules** exported as **ten GF packs**. The Burp plugin and offline
CLI bundle the same packs; installing anything in your home directory is optional for those two paths.
The standalone `gf` command uses the exported JSON files.

```bash
python3 tools/gf/manage.py check
python3 tools/gf/manage.py test-grep
python3 tools/gf/manage.py install --directory ~/.gf

gf rh-secrets-prefixed response.js
gf rh-secrets-context source.env
gf rh-auth-ci saved-http.txt
gf rh-auth-cs source.js
gf rh-private-keys source.txt
gf rh-cloud-locators urls.txt
gf rh-identifiers-cs source.js
gf rh-identifiers-ci source.env
gf rh-network response.txt
gf rh-hints source.js
```

With no `--directory`, the installer chooses `~/.config/gf` if that directory exists, otherwise
`~/.gf`, matching upstream gf's discovery order. Existing unrelated packs are retained. Conflicting
same-name files and symlinks are refused; an identical installation can be repeated. No downloaded
rule or external command is executed during installation. Use a trusted checkout.

The exports use **GNU grep with PCRE support (`-P`)**, with `-i` only in the case-insensitive packs.
This avoids slow POSIX-ERE compilation of large bounded token formats and handles the JSON/quote
escapes consistently. Verify `grep -P` is available on your system. Native Java matching does not
launch grep, gf, shells or any pack's `engine`. A gf command prints matching source lines, which can
contain raw secrets; native findings and report text instead redact matched sensitive values.

| Pack | Coverage / interpretation |
| --- | --- |
| `rh-secrets-prefixed` | GitHub PAT/OAuth/App tokens; classic and routable GitLab families; Google/OAuth, AWS Bedrock, DigitalOcean, Stripe, Square, Braintree, Mailgun, SendGrid, npm/PyPI, Shopify, Vault, Grafana, Slack, OpenAI/Anthropic and other recognizable families. |
| `rh-secrets-context` | Named cloud/LLM/recon provider variables, authentication tokens, password/secret assignments; supports both quoted JSON keys and shell-style assignments. Native entropy and placeholder checks reduce generic noise. |
| `rh-auth-ci`, `rh-auth-cs` | Basic/Bearer, structurally parsed JWT candidates, credential-bearing database/GitHub URLs, signed cloud URLs, webhook credentials and legacy formats. |
| `rh-private-keys` | PKCS#8, RSA, EC, DSA, OpenSSH, encrypted-key and PGP private-key markers. A marker is a lead; it does not establish a complete usable key. |
| `rh-identifiers-cs`, `rh-identifiers-ci` | AWS access-key IDs/ARNs, Twilio SIDs, OAuth client IDs, OCIDs, bare CAPTCHA key formats and publishable keys. A CAPTCHA secret is detected separately by assignment context. These are inventory hints, not usable secret credentials by themselves. |
| `rh-cloud-locators` | S3, API Gateway, CloudFront, Cognito, Azure storage/vault/app/Cosmos, GCP storage/Firebase/Cloud Run/functions, Supabase, Cloudflare Workers and DigitalOcean Spaces. |
| `rh-network` | IPv4/CIDR, compressed/IPv4-mapped/scoped IPv6, hostnames and email candidates. Java validators reject malformed IPs and numeric-only hostname candidates without DNS. |
| `rh-hints` | Interesting variable names and parameter names for manual investigation. |

**Interpretation:** all GF matches are passive SIGNALs, not confirmation of credential validity,
permissions, endpoint exposure or exploitability. Native issues use tentative confidence. Public
identifiers/resource locations have INFO severity and follow the UI's information-finding toggle.
Generic unclassified community packs retain informational reporting, with values redacted by default.
No validity checking, provider API use, replay, scope expansion or automatic target probing is added.

Matched secret values are redacted before entering native finding tables, persistence, issue detail,
SARIF/Markdown export and the offline CLI's report text. GF source URLs omit query/userinfo/fragment,
and redact a matched secret in a decoded path. Original captured HTTP messages can still contain
credentials and remain sensitive evidence; this feature does not sanitize the entire Burp project,
unrelated detector outputs or every surrounding source string.

**Loading and limits:** bundled packs load first, then same-name local overrides, with precedence
`GF_PATTERNS_DIR` → `~/.config/gf` → `~/.gf` → bundled. Plain `pattern` takes precedence over `patterns`,
as in gf. JSON is parsed structurally, including escaped quotes and `]` inside character classes.
The optional `reconhound` schema-1 extension binds rule IDs, categories, capture groups, entropy,
validators and keyword prefilters to the same exported pattern list. Upstream gf ignores this metadata.

Native scanning examines at most the first 1 Mi characters, with 128 match attempts per rule and
2,000 total results. Loading is limited to 128 packs, 1,024 total rules, 256 rules per pack, 512 KiB per
pack and 4,096 characters per expression. Same-rule/value duplicates are suppressed. Load diagnostics
identify rejected file/rule positions without echoing pattern contents. File/search/render flags have
no native process effect; invert/context/file-input modes are rejected instead of being misread as
case-insensitive flags. Java and GNU grep share the curated subset, not every arbitrary PCRE feature.
Local custom regexes are trusted configuration: input/result bounds are **not a regex execution-time
guarantee**. Keyword filtering and bounded curated expressions reduce work; this is not a sandbox
for hostile pattern definitions. The native matcher additionally applies validators and entropy;
standalone gf performs format matching only.

**Maintenance:** edit `gf/catalog.json`, add positive/negative fixtures and provenance, then run:

```bash
python3 tools/gf/manage.py generate
python3 tools/gf/manage.py check
python3 tools/gf/manage.py test-grep
python3 -m unittest discover -s tools/gf/tests -v
./gradlew test --tests 'com.victor.reconloop.Gf*'
```

Fixtures are synthetic and split into fragments in source. Parameterized Java tests verify each
rule's whole captured value, exact offsets and negative cases. Additional tests cover token endings,
adjacent candidates, IP/JWT validation, loader bounds, duplicate/invalid JSON, pack precedence,
redaction through persistence/exports, no target traffic, disabled matching and installer conflicts.
CI rejects stale generated packs and checks grep compatibility separately. Native-only entropy and
validation negatives are explicitly marked, rather than claiming standalone gf performs those checks.

Some token-family patterns were adapted using the MIT-licensed Gitleaks catalog at commit
`b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b`; its license is retained in
`gf/GITLEAKS-LICENSE.txt`. Authored context/inventory heuristics and provider documentation are
identified per rule. Token lengths/prefixes are detector heuristics, not permanent API guarantees.
This is a curated subset with additional recon rules, not a full Gitleaks implementation. In
particular, provider verification, repository/path allowlists, history scanning and complete
upstream rule semantics are not imported.

Relevant provider references: [GitHub token families](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-authentication-to-github),
[GitLab token overview](https://docs.gitlab.com/security/tokens/),
[Stripe key types](https://docs.stripe.com/keys),
[Twilio key SID and secret](https://www.twilio.com/docs/iam/api-keys/key-resource-v1),
[reCAPTCHA client-side site key](https://developers.google.com/recaptcha/docs/display),
[Supabase publishable/secret keys](https://supabase.com/docs/guides/api/api-keys).
