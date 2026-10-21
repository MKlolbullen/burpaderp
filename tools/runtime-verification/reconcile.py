#!/usr/bin/env python3
"""Offline comparison of Burp harness receipts and receiving-fixture observations; never approves release."""
import argparse
import base64
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path

MAX_FILE = 16 * 1024 * 1024
CASE_IDS = {"http", "https", "redirect", "protected-answer", "mixed-answers", "changed-answer", "budget", "cancelled"}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def parse(text):
    def finite_number(value):
        number = float(value)
        if not math.isfinite(number):
            raise ValueError("nonfinite number")
        return number
    return json.loads(text, object_pairs_hook=unique_object, parse_float=finite_number,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite number")))


def load(path, jsonl=False):
    with open(path, "rb") as stream:
        raw = stream.read(MAX_FILE + 1)
    if len(raw) > MAX_FILE:
        raise ValueError("input exceeds 16 MiB")
    text = raw.decode("utf-8")
    if jsonl:
        if not text.endswith("\n"):
            raise ValueError("fixture log is empty or truncated")
        data = [parse(line) for line in text.splitlines()]
    else:
        data = parse(text)
    return data, dict(file=Path(path).name, sha256=hashlib.sha256(raw).hexdigest(), length=len(raw))


def checked_bytes(value, prefix=""):
    encoded = value[prefix + "Base64"] if prefix else value["base64"]
    raw = base64.b64decode(encoded, validate=True)
    if len(raw) > 65536 or base64.b64encode(raw).decode("ascii") != encoded:
        raise ValueError("invalid or oversized bytes")
    length = value[prefix + "Length"] if prefix else value["originalLength"]
    sha = value[prefix + "Sha256"] if prefix else value["sha256"]
    if len(raw) != length or hashlib.sha256(raw).hexdigest() != sha:
        raise ValueError("length/digest mismatch")
    if not prefix and (value["capture"] != "COMPLETE" or value["capturedSha256"] != sha):
        raise ValueError("complete planned/response bytes required")
    return raw


def compare(report, events):
    if not isinstance(report, dict) or not isinstance(events, list) or any(not isinstance(e, dict) for e in events):
        raise ValueError("report/log object shape is invalid")
    if type(report.get("runtimeEvidenceVersion")) is not int or report["runtimeEvidenceVersion"] != 1:
        raise ValueError("unsupported runtime report")
    if not events or any(type(e.get("fixtureVersion")) is not int or e["fixtureVersion"] != 1 for e in events):
        raise ValueError("unsupported fixture log")
    if events[-1]["event"] != "fixture_stop":
        raise ValueError("fixture has no orderly stop marker; capture is incomplete")
    sessions = {e["sessionId"] for e in events}
    if len(sessions) != 1:
        raise ValueError("mixed fixture sessions; use one isolated capture")
    cfg = report["configuration"]
    address = ipaddress.ip_address(cfg["address"])
    requests = [e for e in events if e["event"] == "http_request"]
    responses = [e for e in events if e["event"] == "http_response"]
    accepts = {e["connectionId"]: e for e in events if e["event"] == "tcp_accept"}
    tls = {e["connectionId"]: e for e in events if e["event"] == "tls"}
    if len(accepts) != sum(e["event"] == "tcp_accept" for e in events):
        raise ValueError("duplicate TCP accept identity")
    for event in requests:
        checked_bytes(event, "request")
        accepted = accepts.get(event["connectionId"])
        if accepted is None or accepted["localAddress"] != event["localAddress"] or accepted["localPort"] != event["localPort"]:
            raise ValueError("HTTP observation lacks a matching TCP accept")
        # Treat the marker inside the raw bytes as authoritative, not a detached JSON label.
        raw = checked_bytes(event, "request")
        markers = [line.split(b":", 1)[1].strip().decode("ascii") for line in raw.split(b"\r\n")
                   if line.lower().startswith(b"x-recon-hound-verification:")]
        if markers != [event["marker"]]:
            raise ValueError("fixture marker differs from captured request")
    for event in responses:
        checked_bytes(event, "response")
    issues, rows, used_markers = [], [], set()
    cases = report["cases"]
    if not isinstance(cases, list) or any(not isinstance(case, dict) for case in cases):
        raise ValueError("case shape is invalid")
    ids = [c["id"] for c in cases]
    if len(ids) != len(set(ids)) or not set(ids).issubset(CASE_IDS):
        raise ValueError("duplicate or unknown runtime case")
    if report["state"] != "COMPLETED" or set(ids) != CASE_IDS:
        issues.append("experiment incomplete")
    for case in cases:
        case_issues, attempts = [], []
        markers, expected = case["markers"], case["expectedDispatch"]
        expected_decisions = ({"protected-answer": ["PROTECTED_DESTINATION"], "mixed-answers": ["PROTECTED_DESTINATION"],
            "changed-answer": ["ALLOW", "PROTECTED_DESTINATION"], "budget": ["ALLOW", "ALLOW", "BUDGET_EXHAUSTED"],
            "cancelled": ["CANCELLED"]}).get(case["id"], ["ALLOW"])
        if expected != [d == "ALLOW" for d in expected_decisions] or case["expectedDecisions"] != expected_decisions:
            raise ValueError("case expectations differ from version-1 protocol")
        exchanges = case["evidence"]["exchanges"]
        if len(markers) != len(expected) or len(exchanges) != len(markers) or any(type(v) is not bool for v in expected):
            raise ValueError("invalid attempt shape")
        if (case["apiAdmission"] != "MATCH" or case["responseObservation"] != "MATCH"
                or [e["decision"] for e in exchanges] != expected_decisions
                or [e["dispatchAttempted"] for e in exchanges] != expected
                or case["quotaUsed"] != sum(expected)):
            case_issues.append("API admission/response expectation differs")
        for index, (marker, admitted, exchange) in enumerate(zip(markers, expected, exchanges)):
            if marker != f"{report['experimentId']}/{case['id']}/{index}" or marker in used_markers:
                raise ValueError("invalid or reused attempt marker")
            used_markers.add(marker)
            observed = [e for e in requests if e["marker"] == marker]
            result = dict(marker=marker, receivingRequests=len(observed), physicalPeer="NOT_VERIFIED")
            if not admitted:
                result["fixtureObservation"] = "UNEXPECTED_REQUEST" if observed else "NO_MARKED_HTTP_OBSERVATION"
                result["connectionAbsence"] = "NOT_VERIFIED"
                if observed:
                    case_issues.append("denied attempt reached receiving fixture")
            elif len(observed) != 1:
                result["fixtureObservation"] = "MISSING_REQUEST" if not observed else "EXTRA_REQUESTS"
                case_issues.append("expected exactly one receiving request for admitted API attempt")
            else:
                event = observed[0]
                matches = ipaddress.ip_address(event["localAddress"]) == address and event["localPort"] == cfg["httpsPort" if case["id"] == "https" else "httpPort"]
                matches &= checked_bytes(event, "request") == checked_bytes(exchange["plannedRequest"])
                matches &= event["host"] == f"{cfg['host']}:{cfg['httpsPort'] if case['id'] == 'https' else cfg['httpPort']}"
                if case["id"] == "https":
                    handshake = tls.get(event["connectionId"], {})
                    matches &= event["tls"] is True and event["serverName"] == cfg["host"] and bool(event["tlsProtocol"])
                    matches &= handshake.get("serverName") == cfg["host"] and handshake.get("protocol") == event["tlsProtocol"]
                else:
                    matches &= event["tls"] is False
                replies = [r for r in responses if r["marker"] == marker and r["connectionId"] == event["connectionId"]]
                matches &= len(replies) == 1
                if len(replies) == 1:
                    matches &= checked_bytes(replies[0], "response") == checked_bytes(exchange["response"])
                result["fixtureObservation"] = "MATCHED_RECEIVER_BYTES" if matches else "MISMATCH"
                if not matches:
                    case_issues.append("receiving address/port/Host/SNI/request or response bytes differ")
            attempts.append(result)
        if case_issues:
            issues.extend(f"{case['id']}: {text}" for text in sorted(set(case_issues)))
        rows.append(dict(id=case["id"], attempts=attempts, issues=sorted(set(case_issues))))
    unrelated = [e for e in requests if e["marker"] not in used_markers]
    if unrelated:
        issues.append("unrelated marked HTTP traffic present; capture is not isolated")
    return dict(comparisonVersion=1, experimentId=report["experimentId"], consistentObservations=not issues,
        releaseDecision="NOT_EVALUATED", physicalPeerVerification="NOT_RUN", cases=rows, issues=issues,
        tcpAccepts=len(accepts), tlsErrors=sum(e["event"] == "tls_error" for e in events), unrelatedHttpRequests=len(unrelated),
        limitations="Receiving logs do not prove Burp's first socket peer, intermediate proxy/SOCKS routes, certificate verification, or absence of unmarked/failed connections. Independent packet-capture review and the full matrix remain required.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api-report", required=True)
    parser.add_argument("--fixture-log", required=True)
    parser.add_argument("--output", required=True, help="new JSON path; never overwritten")
    args = parser.parse_args()
    try:
        report, api_manifest = load(args.api_report)
        events, fixture_manifest = load(args.fixture_log, True)
        result = compare(report, events)
        result["inputs"] = [api_manifest, fixture_manifest]
        with os.fdopen(os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w", encoding="utf-8") as out:
            json.dump(result, out, indent=2, ensure_ascii=True)
            out.write("\n")
        print("Observation consistency:", result["consistentObservations"], "| Physical peer: NOT_RUN | Release: NOT_EVALUATED")
        return 0 if result["consistentObservations"] else 1
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as error:
        parser.exit(2, f"Invalid/incomplete evidence: {type(error).__name__}\n")


if __name__ == "__main__":
    raise SystemExit(main())
