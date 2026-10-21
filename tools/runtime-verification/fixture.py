#!/usr/bin/env python3
"""Receiving-only HTTP/1.1/TLS fixture. No DNS lookups, proxying or outbound connections."""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
import signal
import socket
import socketserver
import ssl
import threading
import uuid

MAX_REQUEST = 65536


class EventLog:
    def __init__(self, path):
        self.stream = os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w", encoding="utf-8")
        self.lock = threading.Lock()
        self.session = str(uuid.uuid4())

    def emit(self, event, **values):
        with self.lock:
            self.stream.write(json.dumps(dict(fixtureVersion=1, sessionId=self.session,
                timestamp=datetime.now(timezone.utc).isoformat(), event=event, **values), ensure_ascii=True) + "\n")
            self.stream.flush()

    def close(self):
        if not self.stream.closed:
            self.emit("fixture_stop")
            self.stream.close()


class FixtureServer(socketserver.ThreadingTCPServer):
    daemon_threads = False
    allow_reuse_address = True

    def __init__(self, bind, port, log, label, context=None):
        address = ipaddress.ip_address(bind)  # Require numeric bind; no name resolution.
        self.address_family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
        self.log, self.label, self.context = log, label, context
        super().__init__((str(address), port), Handler)
        log.emit("listen", label=label, localAddress=self.server_address[0], localPort=self.server_address[1], tls=context is not None)

    def get_request(self):
        connection, peer = self.socket.accept()
        connection.settimeout(3)
        identity = str(uuid.uuid4())
        local = connection.getsockname()
        self.log.emit("tcp_accept", label=self.label, connectionId=identity, localAddress=local[0], localPort=local[1], peerAddress=peer[0], peerPort=peer[1])
        if self.context:
            try:
                connection = self.context.wrap_socket(connection, server_side=True)
                self.log.emit("tls", label=self.label, connectionId=identity, serverName=getattr(connection, "fixture_sni", ""), protocol=connection.version())
            except (OSError, ssl.SSLError) as error:
                self.log.emit("tls_error", label=self.label, connectionId=identity, errorType=type(error).__name__)
                connection.close()
                raise
        return (connection, identity), peer

    def shutdown_request(self, request):
        super().shutdown_request(request[0])

    def close_request(self, request):
        # Base shutdown_request calls this override with the unpacked socket.
        (request[0] if isinstance(request, tuple) else request).close()


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        connection, identity = self.request
        data = bytearray()
        try:
            while b"\r\n\r\n" not in data:
                chunk = connection.recv(min(4096, MAX_REQUEST + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
                if len(data) > MAX_REQUEST:
                    raise ValueError("request too large")
            raw = bytes(data)
            if not raw.endswith(b"\r\n\r\n"):
                raise ValueError("incomplete or pipelined request")
            lines = raw[:-4].split(b"\r\n")
            method, path, protocol = lines[0].decode("ascii").split(" ")
            if method != "GET" or protocol != "HTTP/1.1" or not path.startswith("/recon-hound-verification/"):
                raise ValueError("only synthetic fixture GET requests are supported")
            headers = {}
            for line in lines[1:]:
                name, value = line.split(b":", 1)
                name = name.decode("ascii").lower()
                if name in headers:
                    raise ValueError("duplicate header")
                headers[name] = value.strip().decode("ascii")
            if "transfer-encoding" in headers or headers.get("content-length", "0") != "0":
                raise ValueError("request bodies are not supported")
            marker = headers.get("x-recon-hound-verification", "")
            pieces = marker.split("/")
            if len(pieces) != 3 or str(uuid.UUID(pieces[0])) != pieces[0] or not pieces[2].isdigit():
                raise ValueError("missing synthetic verification marker")
            local = connection.getsockname()
            self.server.log.emit("http_request", label=self.server.label, connectionId=identity, marker=marker,
                localAddress=local[0], localPort=local[1], host=headers.get("host", ""), tls=self.server.context is not None,
                serverName=getattr(connection, "fixture_sni", ""), tlsProtocol=connection.version() if self.server.context else "",
                requestBase64=base64.b64encode(raw).decode("ascii"), requestLength=len(raw), requestSha256=hashlib.sha256(raw).hexdigest())
            body = json.dumps(dict(fixture=self.server.label, marker=marker)).encode("ascii")
            status = b"302 Found" if path.endswith("/redirect") else b"200 OK"
            redirect = b"Location: http://127.0.0.1:1/recon-hound-denied\r\n" if path.endswith("/redirect") else b""
            response = (b"HTTP/1.1 " + status + b"\r\nContent-Type: application/json\r\n" + redirect
                + b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\nConnection: close\r\n\r\n" + body)
            connection.sendall(response)
            self.server.log.emit("http_response", label=self.server.label, connectionId=identity, marker=marker,
                responseBase64=base64.b64encode(response).decode("ascii"), responseLength=len(response), responseSha256=hashlib.sha256(response).hexdigest())
        except (OSError, ValueError, UnicodeError) as error:
            self.server.log.emit("request_error", label=self.server.label, connectionId=identity, errorType=type(error).__name__)


def tls_context(cert, key):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert, key)
    context.set_alpn_protocols(["http/1.1"])
    context.set_servername_callback(lambda connection, name, _: setattr(connection, "fixture_sni", name or ""))
    return context


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", required=True, help="numeric address on the operator-controlled fixture host")
    parser.add_argument("--http-port", type=int, default=18080)
    parser.add_argument("--https-port", type=int, default=18443)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--log", required=True, help="new JSONL path; never overwritten")
    args = parser.parse_args()
    log = EventLog(args.log)
    servers = []
    try:
        context = tls_context(args.cert, args.key)
        for port, label, tls in [(args.http_port, "http", None), (args.https_port, "https", context)]:
            server = FixtureServer(args.bind, port, log, label, tls)
            servers.append(server)
            threading.Thread(target=server.serve_forever, daemon=True).start()
        stop = threading.Event()
        for signum in (signal.SIGINT, signal.SIGTERM):
            signal.signal(signum, lambda *_: stop.set())
        print("Receiving fixture ready; HTTP/1.1 only, connection close, no outbound activity.", flush=True)
        stop.wait()
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()
        log.close()


if __name__ == "__main__":
    main()
