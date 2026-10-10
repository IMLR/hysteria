#!/usr/bin/env python3
"""Exercise an auto server using an independent, stock Hysteria v2.13.0 client.

Uses loopback UDP/TCP, temporary certificates and random test passwords only.
Requires Python 3.10+ and openssl. No Python packages or Internet access needed.
"""

import argparse
import concurrent.futures
import contextlib
import json
import os
from pathlib import Path
import secrets
import select
import socket
import socketserver
import struct
import subprocess
import tempfile
import threading
import time


def udp_socket():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    return sock


def free_port(kind):
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def receive(sock, length):
    data = bytearray()
    while len(data) < length:
        block = sock.recv(length - len(data))
        if not block:
            raise RuntimeError("unexpected TCP EOF")
        data.extend(block)
    return bytes(data)


class TCPEcho(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(15)
        while data := self.request.recv(65536):
            self.request.sendall(data)


class UDPEcho(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        sock.sendto(data, self.client_address)


class Relay:
    """Two destination ports and replaceable server-facing UDP source ports."""

    def __init__(self, destination):
        self.destination = destination
        self.fronts = [udp_socket(), udp_socket()]
        self.backs = [udp_socket(), udp_socket()]
        self.clients = {}
        self.seen_ports = set()
        self.rotate = threading.Event()
        self.rotated = threading.Event()
        self.stopped = threading.Event()
        self.drop_every = 0
        self.packet_count = 0
        self.dropped = 0
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    @property
    def address(self):
        ports = ",".join(str(s.getsockname()[1]) for s in self.fronts)
        return "127.0.0.1:" + ports

    def rebind(self):
        self.rotated.clear()
        self.rotate.set()
        assert self.rotated.wait(3), "relay rebind timed out"

    def run(self):
        while not self.stopped.is_set():
            if self.rotate.is_set():
                new_backs = [udp_socket(), udp_socket()]
                for sock in self.backs:
                    sock.close()
                self.backs = new_backs
                self.rotate.clear()
                self.rotated.set()
            ready, _, _ = select.select(self.fronts + self.backs, [], [], 0.05)
            for sock in ready:
                data, addr = sock.recvfrom(65536)
                self.packet_count += 1
                if self.drop_every and self.packet_count % self.drop_every == 0:
                    self.dropped += 1
                    continue
                if sock in self.fronts:
                    index = self.fronts.index(sock)
                    self.clients[index] = addr
                    self.seen_ports.add(sock.getsockname()[1])
                    self.backs[index].sendto(data, self.destination)
                else:
                    index = self.backs.index(sock)
                    if index in self.clients:
                        self.fronts[index].sendto(data, self.clients[index])

    def close(self):
        self.stopped.set()
        self.thread.join(2)
        for sock in self.fronts + self.backs:
            sock.close()


class Processes:
    def __init__(self, directory):
        self.directory = directory
        self.items = []

    def spawn(self, binary, name, mode, config):
        config_path = self.directory / (name + ".json")
        config_path.write_text(json.dumps(config))
        log_path = self.directory / (name + ".log")
        output = log_path.open("w")
        proc = subprocess.Popen(
            [binary, mode, "--disable-update-check", "--config", str(config_path)],
            stdout=output, stderr=subprocess.STDOUT,
        )
        self.items.append((proc, output, log_path))
        return proc, log_path

    def close(self):
        for proc, output, _ in reversed(self.items):
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
            output.close()


def wait_ready(proc, log, text, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"{log.stem} exited before ready")
        if text in log.read_text():
            return
        time.sleep(0.05)
    raise RuntimeError(f"{log.stem} startup timed out")


def connect_socks(port, target):
    sock = socket.create_connection(("127.0.0.1", port), timeout=12)
    try:
        sock.sendall(b"\x05\x01\x00")
        assert receive(sock, 2) == b"\x05\x00"
        sock.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(target[0])
                     + struct.pack("!H", target[1]))
        header = receive(sock, 4)
        assert header[:2] == b"\x05\x00", "SOCKS connection rejected"
        size = {1: 4, 4: 16}.get(header[3])
        if size is None:
            size = receive(sock, 1)[0]
        receive(sock, size + 2)
        return sock
    except BaseException:
        sock.close()
        raise


def check_traffic(client, target, size=262144, udp=True):
    mode, socks_port, udp_port, _ = client
    with connect_socks(socks_port, target) as sock:
        # Keep writes below the echo server's socket buffers.
        for offset in range(0, size, 32768):
            payload = secrets.token_bytes(min(size - offset, 32768))
            sock.sendall(payload)
            assert receive(sock, len(payload)) == payload, mode + " TCP mismatch"
    if udp:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(5)
            for _ in range(5):
                payload = secrets.token_bytes(1000)
                sock.sendto(payload, ("127.0.0.1", udp_port))
                assert sock.recv(2048) == payload, mode + " UDP mismatch"
    return {"mode": mode, "tcp_bytes": size, "udp_echoes": 5 if udp else 0}


def run(args):
    os.umask(0o077)
    password, obfs_password = secrets.token_hex(20), secrets.token_hex(20)
    with tempfile.TemporaryDirectory(prefix="hysteria-auto-test-") as folder:
        directory = Path(folder)
        processes = Processes(directory)
        relays = []
        with contextlib.ExitStack() as stack:
            stack.callback(processes.close)
            try:
                tcp = stack.enter_context(socketserver.ThreadingTCPServer(
                    ("127.0.0.1", 0), TCPEcho))
                tcp.daemon_threads = True
                udp = stack.enter_context(socketserver.ThreadingUDPServer(
                    ("127.0.0.1", 0), UDPEcho))
                for echo in (tcp, udp):
                    threading.Thread(target=echo.serve_forever, daemon=True).start()
                    stack.callback(echo.shutdown)
                cert, key = directory / "cert.pem", directory / "key.pem"
                subprocess.run([
                    "openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt",
                    "ec_paramgen_curve:prime256v1", "-nodes", "-days", "1",
                    "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
                    "-keyout", str(key), "-out", str(cert),
                ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                server_port = free_port(socket.SOCK_DGRAM)
                server_config = {
                    "listen": f"127.0.0.1:{server_port}",
                    "tls": {"cert": str(cert), "key": str(key)},
                    "auth": {"type": "password", "password": password},
                    "obfs": {"type": "auto", "auto": {"password": obfs_password}},
                }
                proc, log = processes.spawn(args.server, "server", "server", server_config)
                wait_ready(proc, log, "server up and running")
                clients = []
                configs = {}
                for mode in ("plain", "salamander", "gecko"):
                    relay = Relay(("127.0.0.1", server_port))
                    relays.append(relay)
                    stack.callback(relay.close)
                    socks_port = free_port(socket.SOCK_STREAM)
                    udp_port = free_port(socket.SOCK_DGRAM)
                    config = {
                        "server": relay.address, "auth": password,
                        "tls": {"sni": "localhost", "ca": str(cert)},
                        "transport": {"type": "udp", "udp": {"hopInterval": "5s"}},
                        "socks5": {"listen": f"127.0.0.1:{socks_port}"},
                        "udpForwarding": [{"listen": f"127.0.0.1:{udp_port}",
                                           "remote": "%s:%s" % udp.server_address}],
                    }
                    if mode != "plain":
                        config["obfs"] = {"type": mode, mode: {"password": obfs_password}}
                    configs[mode] = config
                    proc, log = processes.spawn(args.client, mode, "client", config)
                    wait_ready(proc, log, "SOCKS5 server listening")
                    clients.append((mode, socks_port, udp_port, relay))
                with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
                    def check_all(phase, **kwargs):
                        futures = [pool.submit(check_traffic, c, tcp.server_address, **kwargs)
                                   for c in clients]
                        results = [future.result() for future in futures]
                        if phase:
                            print(json.dumps({"phase": phase, "results": results}), flush=True)

                    check_all("simultaneous_modes_same_server_port")
                    for relay in relays:
                        relay.rebind()
                    check_all("NAT_rebinding")
                    # Continue exercising live sessions until both hop ports
                    # have actually carried packets, instead of merely waiting.
                    deadline = time.monotonic() + 60
                    while any(len(r.seen_ports) < 2 for r in relays):
                        assert time.monotonic() < deadline, "hop ports were not both used"
                        check_all(None, size=32768)
                        time.sleep(0.4)
                    check_all("port_hopping")
                    for relay in relays:
                        relay.drop_every = 23
                    check_all("TCP_with_packet_loss", size=524288, udp=False)
                    assert all(r.dropped > 0 for r in relays)

                # Plain transport still requires Hysteria authentication.
                invalid = dict(configs["plain"])
                invalid["auth"] = "incorrect-authentication-password"
                invalid["socks5"] = {"listen": f"127.0.0.1:{free_port(socket.SOCK_STREAM)}"}
                invalid.pop("udpForwarding")
                proc, log = processes.spawn(args.client, "bad-auth", "client", invalid)
                proc.wait(timeout=15)
                assert proc.returncode != 0 and "authentication" in log.read_text().lower()

                invalid = dict(configs["salamander"])
                invalid["obfs"] = {"type": "salamander", "salamander": {"password": "wrong-obfs"}}
                invalid["quic"] = {"maxIdleTimeout": "4s"}
                invalid["socks5"] = {"listen": f"127.0.0.1:{free_port(socket.SOCK_STREAM)}"}
                invalid.pop("udpForwarding")
                proc, log = processes.spawn(args.client, "bad-obfs", "client", invalid)
                proc.wait(timeout=15)
                assert proc.returncode != 0 and "SOCKS5 server listening" not in log.read_text()
                print("PASS: all three modes, TCP/UDP, rebinding, hopping, loss, invalid credentials",
                      flush=True)
            except BaseException:
                for _, _, log in processes.items:
                    text = log.read_text().replace(password, "<auth>").replace(obfs_password, "<obfs>")
                    print(log.name, "\n" + "\n".join(text.splitlines()[-12:]), flush=True)
                raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", required=True, help="path to the custom auto server binary")
    parser.add_argument("--client", required=True, help="path to an unmodified v2.13.0 binary")
    arguments = parser.parse_args()
    arguments.server = str(Path(arguments.server).resolve())
    arguments.client = str(Path(arguments.client).resolve())
    run(arguments)
