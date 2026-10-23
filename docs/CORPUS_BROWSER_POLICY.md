# Automated browser corpus policy

The generic corpus previously treated XSS entries as ordinary parameter mutations. The bundled file
also contained remote scripts/iframes and browser redirects. Those entries could be sent without
the persistent-browser grant, and curl/wget callback rewriting did not control browser URLs.

`CorpusBrowserPolicy` now classifies raw source before encoding in both planning and execution:

| Source | Automated behavior | Required grants |
| --- | --- | --- |
| Exact reviewed local marker | Keep the reviewed source; apply the selected encoding | Persistent / stored browser payload |
| Exact controlled beacon recipe | Replace `{{RECON_OAST_HOST}}` with a newly issued Collaborator hostname before encoding | Persistent / stored browser payload **and** OAST |
| Other XSS entry, including remote resources, redirects, encoded or obfuscated code | Quarantine; omit from preview and execution | No grant enables it |
| Browser-shaped source in another category | Quarantine, preventing a category rename from weakening the gate for recognized browser source | No grant enables it |
| Ordinary non-browser corpus entry | Existing destructive filtering, timing/callback permissions and local/run quotas | Existing applicable grants |

The exact local-marker set contains reviewed script/SVG/details/JavaScript markers with local
alert/prompt/confirm behavior. It excludes remote-resource attributes, navigation and dynamic code
loaders. The controlled beacon is a fixed script-src recipe; only the trusted Collaborator API's
fresh DNS hostname can fill its host slot. URL, path, IP literal and markup values fail binding.
Unknown XSS strings are not made executable by replacing a visible URL or matching a loose regex.
The cross-category browser-shape check is additional quarantine, not proof that arbitrary JavaScript
or arbitrary interpreter input is network-free.

Original third-party entries remain in the source file for review. Adding a line to `xss.txt`,
including through a custom payload directory, does not approve it for automation. Expanding coverage
requires explicitly reviewing and registering another local recipe or designing another typed
callback recipe, with preview/runtime/encoding and permission regression tests. This deliberately
reduces automatic execution of unreviewed browser payloads.

All browser markers can execute later if the target stores them. Revoking a grant stops queued and
future dispatches; it cannot remove a payload already stored at a target. A callback confirms an
interaction and retains its run/capture association, not browser execution or exploit impact.
Non-safe HTTP methods and multipart replays keep their separate method/state/upload requirements.
Preview allocates no callbacks and sends nothing. Runtime uses the same raw policy for every
encoding and enters the normal mandatory gateway for every eligible request. Retries rebuild the
recipe from current data, current grants and fresh callback identifiers.

`CorpusBrowserPermissionIntegrationTest` exercises all seven encodings, the four independent browser
risk grant combinations, preview/template parity, no DNS/HTTP/quota on denial, quarantine with every
grant, cross-category browser code, separate POST permission and invalid callback host binding.
