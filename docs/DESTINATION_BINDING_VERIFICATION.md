# Burp destination-binding runtime verification

Status on 2026-10-19: **NOT RUN**. This workspace has a Montoya API JAR and in-memory fixtures, not a
running Burp Suite instance. CI proves API arguments/bytes, cancellation and quotas; it cannot prove
which TCP peer Burp reaches. Do not close issue #44 or claim wire-level destination enforcement from
those tests.

## Contracts under test

- Logical URL scope and `RequestPlan` bind the original message/service.
- The gateway resolves and validates every returned A/AAAA address before quota reservation.
- The Montoya transport is given a numeric service, original bytes, no automatic redirects, and
  original DNS hostname SNI for TLS. It does not use `HttpService.ipAddress()`.
- Returned evidence retains real message bytes and timing while using the logical service in the app.

## Fixture and evidence

Use an authorized lab with two independently observable endpoints and controlled DNS. Run Burp with
the built extension, explicit target scope and recorded grants/limits. Capture resolver answers,
Burp version/edition, network settings, selected destination, gateway/API count, endpoint access logs
and packet capture at the actual egress hop. Use synthetic authentication values. Packet captures and
settings exports may contain credentials; redact them before sharing. A redirect denial must be
proved by absence of a destination connection/request, not only by the source application's error.
Public fixtures must use addresses controlled by the operator; example/documentation ranges are
intentionally blocked and are not executable targets. Never weaken production classification to make
a loopback test appear representative of a public destination.

| Runtime case | Required observation | Status |
| --- | --- | --- |
| Direct HTTP, one public A record | Exactly one connection to the checked numeric IP; unchanged Host/path/body; logical finding URL | NOT RUN |
| Direct HTTPS, virtual host | Numeric TCP destination, original SNI, intended virtual-host response; document actual TLS verification policy | NOT RUN |
| IPv6-only public destination | Checked canonical IPv6 service is honored; no alternate name lookup | NOT RUN |
| Mixed A/AAAA with protected answer | No target API dispatch, token or target connection | NOT RUN |
| DNS rebinding between sends | Each admitted dispatch uses its checked numeric address; protected result blocks next request | NOT RUN |
| In-scope redirect to protected-resolving hostname | Redirect response returned; no protected hop is connected or charged | NOT RUN |
| Two logical hosts sharing one IP | Correct Host/authority and SNI for each; inspect reuse/coalescing and TLS sessions | NOT RUN |
| Burp upstream HTTP proxy | Observe proxy CONNECT/absolute-form routing; determine whether the checked numeric destination is honored and whether request bytes are rewritten | NOT RUN |
| SOCKS with local/remote DNS | Observe SOCKS destination/address type and any DNS; prove the proxy cannot resolve a logical name in place of the pin | NOT RUN |
| Burp hostname-resolution override | Test overrides matching logical host and numeric service; observe whether Burp changes the destination after admission | NOT RUN |
| Session rules / other extension mutation | Record actual destination and returned request bytes; prove or explicitly exclude post-admission rewrites | NOT RUN |
| Existing connection reuse / reconnect / retry | Record every peer and HTTP request; no assertion that one API call equals one TCP attempt | NOT RUN |
| Cancellation / grant revocation during DNS | No quota reservation or target dispatch when DNS returns; UI need not wait for OS resolver shutdown | NOT RUN |
| Budget N with concurrent preparations | At most N Montoya dispatches; separately count wire retries/auxiliary requests | NOT RUN |
| Unsupported API behavior / byte rewrite | Fail closed before target dispatch; preserve a useful denial reason | NOT RUN |

## Release decision

Keep an explicit record of supported and excluded Burp/network configurations. If any supported
configuration can route around the checked numeric service, add enforceable controlled egress or
remove that configuration's active execution capability before claiming the connection-path gate is
complete. A one-time settings inspection is not atomic with sending and cannot establish this
invariant. This matrix alone is validation planning, not an implementation of peer enforcement.

Bounded [versioned finding evidence](ACTIVE_EVIDENCE.md) is implemented separately; durable full-run
audit/approval records remain separate work. Disabled external HTTP producers must stay disabled until equivalent enforcement
exists; an opt-in or proxy flag does not satisfy this test.
