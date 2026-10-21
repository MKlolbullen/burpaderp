import base64
import copy
import hashlib
import json
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import fixture
import reconcile


def raw_request(marker, redirect=False):
    return (f"GET /recon-hound-verification/{marker}" + ("/redirect" if redirect else "") + " HTTP/1.1\r\n"
        + f"Host: fixture.example.test:18080\r\nX-Recon-Hound-Verification: {marker}\r\nConnection: close\r\n\r\n").encode("ascii")


def captured(raw):
    sha = hashlib.sha256(raw).hexdigest()
    return dict(originalLength=len(raw), sha256=sha, capturedSha256=sha, base64=base64.b64encode(raw).decode("ascii"), capture="COMPLETE")


def event_bytes(raw, prefix):
    return {prefix + "Base64": base64.b64encode(raw).decode("ascii"), prefix + "Length": len(raw), prefix + "Sha256": hashlib.sha256(raw).hexdigest()}


def experiment():
    experiment_id, session = str(uuid.uuid4()), str(uuid.uuid4())
    cfg = dict(host="fixture.example.test", address="93.184.216.34", httpPort=18080, httpsPort=18443)
    report = dict(runtimeEvidenceVersion=1, experimentId=experiment_id, configuration=cfg, state="COMPLETED", cases=[])
    events = [dict(fixtureVersion=1, sessionId=session, event="listen")]
    for name in sorted(reconcile.CASE_IDS):
        decisions = ({"protected-answer": ["PROTECTED_DESTINATION"], "mixed-answers": ["PROTECTED_DESTINATION"],
            "changed-answer": ["ALLOW", "PROTECTED_DESTINATION"], "budget": ["ALLOW", "ALLOW", "BUDGET_EXHAUSTED"],
            "cancelled": ["CANCELLED"]}).get(name, ["ALLOW"])
        expected, markers, exchanges = [d == "ALLOW" for d in decisions], [], []
        for i, admitted in enumerate(expected):
            marker = f"{experiment_id}/{name}/{i}"
            markers.append(marker)
            raw = raw_request(marker)
            if name == "https":
                raw = raw.replace(b":18080", b":18443")
            response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
            exchanges.append(dict(decision=decisions[i], dispatchAttempted=admitted, plannedRequest=captured(raw), response=captured(response)))
            if not admitted:
                continue
            identity = str(uuid.uuid4())
            common = dict(fixtureVersion=1, sessionId=session, connectionId=identity)
            local = dict(localAddress=cfg["address"], localPort=cfg["httpsPort"] if name == "https" else cfg["httpPort"])
            events.append(dict(common, event="tcp_accept", **local))
            if name == "https":
                events.append(dict(common, event="tls", serverName=cfg["host"], protocol="TLSv1.3"))
            events.append(dict(common, event="http_request", marker=marker, **local, host=f"{cfg['host']}:{local['localPort']}",
                tls=name == "https", serverName=cfg["host"] if name == "https" else "", tlsProtocol="TLSv1.3" if name == "https" else "", **event_bytes(raw, "request")))
            events.append(dict(common, event="http_response", marker=marker, **event_bytes(response, "response")))
        report["cases"].append(dict(id=name, markers=markers, expectedDispatch=expected, expectedDecisions=decisions, evidence=dict(exchanges=exchanges),
            apiAdmission="MATCH", responseObservation="MATCH", quotaUsed=sum(expected)))
    events.append(dict(fixtureVersion=1, sessionId=session, event="fixture_stop"))
    return report, events


class ReceiverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cert_dir = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.cert_dir.cleanup)
        cls.cert, cls.key = Path(cls.cert_dir.name) / "cert.pem", Path(cls.cert_dir.name) / "key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=fixture.example.test",
            "-addext", "subjectAltName=DNS:fixture.example.test", "-keyout", str(cls.key), "-out", str(cls.cert)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "fixture.jsonl"
        self.log = fixture.EventLog(self.path)
        self.addCleanup(self.log.close)

    def server(self, tls=False):
        server = fixture.FixtureServer("127.0.0.1", 0, self.log, "test", fixture.tls_context(self.cert, self.key) if tls else None)
        threading.Thread(target=lambda: server.serve_forever(poll_interval=0.01), daemon=True).start()
        self.addCleanup(lambda: (server.shutdown(), server.server_close()))
        return server

    def send(self, server, raw, tls=False):
        connection = socket.create_connection(("127.0.0.1", server.server_address[1]), timeout=3)
        if tls:
            context = ssl.create_default_context(cafile=str(self.cert))
            connection = context.wrap_socket(connection, server_hostname="fixture.example.test")
        with connection:
            connection.sendall(raw)
            result = bytearray()
            while True:
                part = connection.recv(8192)
                if not part:
                    return bytes(result)
                result.extend(part)

    def events(self):
        return [json.loads(line) for line in self.path.read_text().splitlines()]

    def test_http_socket_records_actual_local_address_raw_bytes_and_response(self):
        server = self.server()
        marker = f"{uuid.uuid4()}/http/0"
        raw = raw_request(marker)
        response = self.send(server, raw)
        events = self.events()
        request = next(e for e in events if e["event"] == "http_request")
        self.assertEqual(raw, reconcile.checked_bytes(request, "request"))
        self.assertEqual("127.0.0.1", request["localAddress"])
        self.assertEqual(server.server_address[1], request["localPort"])
        self.assertFalse(request["tls"])
        self.assertEqual(response, reconcile.checked_bytes(next(e for e in events if e["event"] == "http_response"), "response"))
        self.assertEqual(1, sum(e["event"] == "tcp_accept" for e in events))

    def test_tls_handshake_records_real_sni_and_raw_http(self):
        server = self.server(tls=True)
        raw = raw_request(f"{uuid.uuid4()}/https/0")
        response = self.send(server, raw, tls=True)
        self.assertTrue(response.startswith(b"HTTP/1.1 200"))
        tls = next(e for e in self.events() if e["event"] == "tls")
        request = next(e for e in self.events() if e["event"] == "http_request")
        self.assertEqual("fixture.example.test", tls["serverName"])
        self.assertEqual(tls["protocol"], request["tlsProtocol"])
        self.assertEqual(raw, reconcile.checked_bytes(request, "request"))

    def test_redirect_returns_location_without_any_outbound_receiver_connection(self):
        server = self.server()
        response = self.send(server, raw_request(f"{uuid.uuid4()}/redirect/0", True))
        self.assertTrue(response.startswith(b"HTTP/1.1 302"))
        self.assertIn(b"Location: http://127.0.0.1:1/recon-hound-denied", response)
        self.assertEqual(1, sum(e["event"] == "tcp_accept" for e in self.events()))

    def test_invalid_request_still_records_tcp_accept_and_error_without_http_observation(self):
        server = self.server()
        self.send(server, b"GET /unrelated HTTP/1.1\r\nHost: test\r\n\r\n")
        self.assertEqual(["listen", "tcp_accept", "request_error"], [e["event"] for e in self.events()])

    def test_log_never_overwrites_existing_evidence(self):
        before = self.path.read_bytes()
        with self.assertRaises(FileExistsError):
            fixture.EventLog(self.path)
        self.assertEqual(before, self.path.read_bytes())


class ComparisonTests(unittest.TestCase):
    def test_consistent_bytes_and_denials_do_not_approve_release_or_attest_peer_absence(self):
        report, events = experiment()
        result = reconcile.compare(report, events)
        self.assertTrue(result["consistentObservations"], result["issues"])
        self.assertEqual("NOT_EVALUATED", result["releaseDecision"])
        self.assertEqual("NOT_RUN", result["physicalPeerVerification"])
        denied = next(c for c in result["cases"] if c["id"] == "protected-answer")["attempts"][0]
        self.assertEqual("NOT_VERIFIED", denied["connectionAbsence"])
        self.assertEqual(6, result["tcpAccepts"])

    def test_wrong_destination_port_sni_or_changed_request_bytes_are_mismatches(self):
        for change in ["address", "port", "sni", "request", "response"]:
            report, events = experiment()
            request = next(e for e in events if e["event"] == "http_request" and e["tls"])
            if change == "address":
                report["configuration"]["address"] = "8.8.8.8"
            elif change == "port":
                report["configuration"]["httpsPort"] = 443
            elif change == "sni":
                request["serverName"] = "wrong.test"
            elif change == "request":
                raw = reconcile.checked_bytes(request, "request").replace(b"Connection: close", b"X-Session-Rule: changed")
                request.update(event_bytes(raw, "request"))
            else:
                response = next(e for e in events if e["event"] == "http_response")
                response.update(event_bytes(b"HTTP/1.1 403 Denied\r\n\r\n", "response"))
            self.assertFalse(reconcile.compare(report, events)["consistentObservations"], change)

    def test_retries_duplicate_receiving_requests_and_missing_requests_are_visible(self):
        report, events = experiment()
        index = next(i for i, e in enumerate(events) if e["event"] == "http_request")
        events.insert(-1, copy.deepcopy(events[index]))
        self.assertFalse(reconcile.compare(report, events)["consistentObservations"])
        events.pop(-2)
        events.pop(index)
        self.assertFalse(reconcile.compare(report, events)["consistentObservations"])

    def test_denied_attempt_reaching_fixture_is_reported_as_unexpected(self):
        report, events = experiment()
        event = copy.deepcopy(next(e for e in events if e["event"] == "http_request"))
        event["marker"] = f"{report['experimentId']}/protected-answer/0"
        event.update(event_bytes(raw_request(event["marker"]), "request"))
        events.insert(-1, event)
        result = reconcile.compare(report, events)
        self.assertFalse(result["consistentObservations"])
        self.assertTrue(any("denied attempt" in issue for issue in result["issues"]))

    def test_schema_truncation_duplicate_keys_and_digest_errors_fail_without_positive_result(self):
        with self.assertRaises(ValueError):
            reconcile.parse('{"version":1,"version":2}')
        for malformed in ["1e999", "NaN", "Infinity"]:
            with self.assertRaises(ValueError):
                reconcile.parse(malformed)
        report, events = experiment()
        with self.assertRaises(ValueError):
            reconcile.compare(report, events[:-1])
        with self.assertRaises(ValueError):
            reconcile.compare([], events)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.jsonl"
            path.write_text('{"fixtureVersion":1}')
            with self.assertRaises(ValueError):
                reconcile.load(path, True)
        report, events = experiment()
        report["runtimeEvidenceVersion"] = 2
        with self.assertRaises(ValueError):
            reconcile.compare(report, events)
        report["runtimeEvidenceVersion"] = 1
        event = next(e for e in events if e["event"] == "http_request")
        event["requestSha256"] = "0" * 64
        with self.assertRaises(ValueError):
            reconcile.compare(report, events)

    def test_incomplete_or_altered_case_protocol_cannot_report_consistency(self):
        report, events = experiment()
        report["state"] = "CANCELLED"
        self.assertFalse(reconcile.compare(report, events)["consistentObservations"])
        report["state"] = "COMPLETED"
        report["cases"][0]["expectedDecisions"] = ["ALLOW"]
        with self.assertRaises(ValueError):
            reconcile.compare(report, events)

    def test_cli_hashes_inputs_and_preserves_existing_output(self):
        report, events = experiment()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            api, log, output = root / "api.json", root / "fixture.jsonl", root / "comparison.json"
            api.write_text(json.dumps(report))
            log.write_text("".join(json.dumps(e) + "\n" for e in events))
            command = [sys.executable, str(Path(reconcile.__file__)), "--api-report", str(api), "--fixture-log", str(log), "--output", str(output)]
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(0, result.returncode, result.stderr)
            parsed = json.loads(output.read_text())
            self.assertEqual(hashlib.sha256(api.read_bytes()).hexdigest(), parsed["inputs"][0]["sha256"])
            before = output.read_bytes()
            self.assertEqual(2, subprocess.run(command, capture_output=True).returncode)
            self.assertEqual(before, output.read_bytes())


if __name__ == "__main__":
    unittest.main()
