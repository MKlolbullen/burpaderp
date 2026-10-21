package com.victor.reconloop;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import java.net.URI;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.atomic.*;
import java.util.function.Consumer;

/** Opt-in runtime experiment, using the unchanged production gate/transport and current Burp scope. */
final class RuntimeVerificationCases {
    record Config(String host, String address, int httpPort, int httpsPort, String directResolver, String profile) {
        static Config parse(String json) {
            Map<String, Object> o = Json.asObject(Json.parseStrict(json));
            if (o == null || !o.keySet().equals(Set.of("host", "address", "httpPort", "httpsPort", "directResolver", "profile")))
                throw new IllegalArgumentException("Expected host, address, httpPort, httpsPort, directResolver and profile only");
            String host = text(o, "host"), address = text(o, "address"), resolver = text(o, "directResolver"), profile = text(o, "profile");
            var h = DestinationAddress.inspect(host); var a = DestinationAddress.inspect(address);
            if (h.kind() != DestinationAddress.Kind.NAME || !h.canonical().equals(host) || !host.contains("."))
                throw new IllegalArgumentException("host must be a canonical DNS hostname for the operator's fixture");
            if (a.kind() != DestinationAddress.Kind.PUBLIC || !a.canonical().equals(address))
                throw new IllegalArgumentException("address must be a canonical public numeric address controlled by the operator");
            if (!Set.of("system", "controlled").contains(resolver) || !profile.matches("[A-Za-z0-9 ._:/-]{1,128}"))
                throw new IllegalArgumentException("Invalid directResolver or profile label");
            return new Config(host, address, port(o, "httpPort"), port(o, "httpsPort"), resolver, profile);
        }
        private static String text(Map<String, Object> o, String key) {
            if (!(o.get(key) instanceof String s) || s.length() > 256) throw new IllegalArgumentException("Invalid " + key);
            return s;
        }
        private static int port(Map<String, Object> o, String key) {
            if (!(o.get(key) instanceof Number n) || n.doubleValue() != n.intValue() || n.intValue() < 1 || n.intValue() > 65535)
                throw new IllegalArgumentException("Invalid port");
            return n.intValue();
        }
        String url(boolean tls, String path) {
            try { return new URI(tls ? "https" : "http", null, host, tls ? httpsPort : httpPort, path, null, null).toString(); }
            catch (java.net.URISyntaxException e) { throw new IllegalArgumentException(e); }
        }
        Map<String, Object> map() { return obj("host", host, "address", address, "httpPort", httpPort, "httpsPort", httpsPort,
                "directResolver", directResolver, "profile", profile); }
    }

    private final MontoyaApi api;
    private final AtomicBoolean cancelled = new AtomicBoolean();
    private final AtomicReference<ScanRun> current = new AtomicReference<>();
    RuntimeVerificationCases(MontoyaApi api) { this.api = Objects.requireNonNull(api); }
    void cancel() { cancelled.set(true); ScanRun run = current.get(); if (run != null) run.cancel(); }

    Map<String, Object> run(Config config, Consumer<Map<String, Object>> checkpoint) {
        String experiment = UUID.randomUUID().toString();
        Map<String, Object> report = obj("runtimeEvidenceVersion", 1, "experimentId", experiment, "startedAt", Instant.now().toString(),
                "burpVersion", version(), "javaVersion", System.getProperty("java.version"), "configuration", config.map(),
                "state", "RUNNING", "releaseDecision", "NOT_EVALUATED", "physicalPeerVerification", "NOT_RUN",
                "limitations", "API receipts and receiving-fixture logs cannot attest Burp's physical peer, proxy/SOCKS routing, retries or absence of connections. Review independent packet capture and the full runtime matrix.",
                "cases", new ArrayList<Map<String, Object>>());
        List<Map<String, Object>> cases = new ArrayList<>();
        checkpoint.accept(report);
        if (!api.scope().isInScope(config.url(false, "/")) || !api.scope().isInScope(config.url(true, "/"))) {
            report.put("state", "NOT_RUN"); report.put("reason", "Both fixture origins must already be in Burp scope; the harness never changes scope.");
            checkpoint.accept(report); return report;
        }
        for (String id : List.of("http", "https", "redirect", "protected-answer", "mixed-answers", "changed-answer", "budget", "cancelled")) {
            if (cancelled.get()) break;
            cases.add(execute(config, experiment, id));
            report.put("cases", List.copyOf(cases)); checkpoint.accept(report);
        }
        report.put("state", cancelled.get() ? "CANCELLED" : "COMPLETED"); report.put("finishedAt", Instant.now().toString());
        checkpoint.accept(report); return report;
    }

    private Map<String, Object> execute(Config c, String experiment, String id) {
        boolean tls = id.equals("https");
        int attempts = id.equals("budget") ? 3 : id.equals("changed-answer") ? 2 : 1;
        List<String> expected = switch (id) {
            case "protected-answer", "mixed-answers" -> List.of("PROTECTED_DESTINATION");
            case "changed-answer" -> List.of("ALLOW", "PROTECTED_DESTINATION");
            case "budget" -> List.of("ALLOW", "ALLOW", "BUDGET_EXHAUSTED");
            case "cancelled" -> List.of("CANCELLED");
            default -> List.of("ALLOW");
        };
        AtomicInteger resolutions = new AtomicInteger();
        boolean direct = Set.of("http", "https", "redirect", "budget").contains(id);
        DestinationGuard guard = direct && c.directResolver().equals("system") ? DestinationGuard.system() : new DestinationGuard(host -> {
            if (!host.equals(c.host())) throw new IllegalArgumentException("Unexpected fixture host");
            return switch (id) {
                case "protected-answer" -> List.of("127.0.0.1");
                case "mixed-answers" -> List.of(c.address(), "127.0.0.1");
                case "changed-answer" -> List.of(resolutions.getAndIncrement() == 0 ? c.address() : "127.0.0.1");
                default -> List.of(c.address());
            };
        });
        ScanRun run = ScanRun.begin(ScanProfile.ACTIVE_SAFE, ScopeSnapshot.empty(), id.equals("budget") ? 2 : 4);
        current.set(run);
        if (id.equals("cancelled") || cancelled.get()) run.cancel();
        ActiveRequestGateway gateway = new ActiveRequestGateway(RequestPolicy.safeDefault(api.scope()::isInScope), new MontoyaTargetTransport(api, guard));
        String path = "/recon-hound-verification/" + experiment + "/" + id + (id.equals("redirect") ? "/redirect" : "");
        List<String> markers = new ArrayList<>(), decisions = new ArrayList<>(); List<Integer> statuses = new ArrayList<>();
        List<Boolean> dispatched = new ArrayList<>(); EvidenceCapture capture = null;
        String started = Instant.now().toString();
        try {
            for (int i = 0; i < attempts; i++) {
                if (cancelled.get()) run.cancel();
                String marker = experiment + "/" + id + "/" + i; markers.add(marker);
                HttpRequest request = HttpRequest.httpRequest(HttpService.httpService(c.host(), tls ? c.httpsPort() : c.httpPort(), tls),
                        "GET " + path + " HTTP/1.1\r\nHost: " + c.host() + ":" + (tls ? c.httpsPort() : c.httpPort())
                                + "\r\nX-Recon-Hound-Verification: " + marker + "\r\nAccept: application/json\r\nConnection: close\r\n\r\n");
                if (capture == null) capture = new EvidenceCapture(run, request, "NATIVE_HELPER", "runtime-" + id);
                var result = gateway.send(run, RequestPlan.safe(request, "runtime-" + id), request); capture.record(result);
                decisions.add(result.decision().code().name()); dispatched.add(result.dispatched());
                statuses.add(result.response() == null || result.response().response() == null ? -1 : (int) result.response().response().statusCode());
            }
            var evidence = capture.snapshot(VerificationState.SIGNAL, "Runtime experiment observations, not a vulnerability finding or release attestation.");
            List<Boolean> expectedDispatch = expected.stream().map("ALLOW"::equals).toList();
            List<Integer> expectedStatuses = expected.stream().map(d -> d.equals("ALLOW") ? (id.equals("redirect") ? 302 : 200) : -1).toList();
            return obj("id", id, "startedAt", started, "finishedAt", Instant.now().toString(), "resolver", direct ? c.directResolver() : "controlled",
                    "markers", markers, "expectedDecisions", expected, "observedDecisions", decisions, "expectedDispatch", expectedDispatch,
                    "observedDispatch", dispatched, "expectedStatusCodes", expectedStatuses, "observedStatusCodes", statuses,
                    "quotaUsed", run.requestBudget().used(), "apiAdmission", expected.equals(decisions) && expectedDispatch.equals(dispatched) ? "MATCH" : "MISMATCH",
                    "responseObservation", expectedStatuses.equals(statuses) ? "MATCH" : "MISMATCH", "wireStatus", "NOT_EVALUATED",
                    "evidence", ActiveEvidenceCodec.evidenceMap(evidence));
        } finally { current.compareAndSet(run, null); if (run.isRunning()) run.complete(); }
    }

    private String version() {
        try { return api.burpSuite().version() + " / " + api.burpSuite().version().edition(); }
        catch (RuntimeException unavailable) { return "unavailable"; }
    }
    static Map<String, Object> obj(Object... pairs) {
        Map<String, Object> o = new LinkedHashMap<>(); for (int i = 0; i < pairs.length; i += 2) o.put((String) pairs[i], pairs[i + 1]); return o;
    }
}
