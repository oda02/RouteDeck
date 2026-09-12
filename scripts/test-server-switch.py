"""Explicit integration fixture: pinned sing-box, loopback only, no TUN or host changes.

python scripts/test-server-switch.py --runtime-root <existing portable directory>
Optional --generated-dir checks the Rust-exported synthetic TUN/Xray configs (check only).
Nothing is downloaded. Only this script's own child is terminated.
"""
import argparse
import contextlib
import hashlib
import http.client
import json
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]


def exact(sock, size):
    data = b""
    while len(data) < size:
        part = sock.recv(size - len(data))
        if not part:
            raise EOFError("Fixture connection closed")
        data += part
    return data


def address(sock, allow_unspecified=False):
    kind = exact(sock, 1)[0]
    if kind == 1:
        host = socket.inet_ntoa(exact(sock, 4))
    elif kind == 3:
        host = exact(sock, exact(sock, 1)[0]).decode("ascii")
    elif kind == 4 and allow_unspecified:
        raw = exact(sock, 16)
        assert raw == bytes(16), "Only unspecified IPv6 in SOCKS UDP association is allowed"
        host = "0.0.0.0"
    else:
        raise AssertionError("Only IPv4 loopback fixture addresses are allowed")
    port = struct.unpack("!H", exact(sock, 2))[0]
    assert host == "127.0.0.1" or (allow_unspecified and host == "0.0.0.0"), "Fixture must never connect outside loopback"
    return "127.0.0.1", port


def bound(kind=socket.SOCK_STREAM):
    sock = socket.socket(socket.AF_INET, kind)
    sock.bind(("127.0.0.1", 0))
    sock.settimeout(3)
    return sock


class SocksFixture:
    """A local SOCKS server whose TCP/UDP responses identify the selected exit."""
    def __init__(self, label):
        self.label = label
        self.listener = bound()
        self.port = self.listener.getsockname()[1]
        self.listener.listen()
        self.closed = threading.Event()
        self.sockets = [self.listener]
        threading.Thread(target=self.accept, daemon=True).start()

    def accept(self):
        while not self.closed.is_set():
            try:
                conn, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            self.sockets.append(conn)
            threading.Thread(target=self.serve, args=(conn,), daemon=True).start()

    def serve(self, conn):
        try:
            conn.settimeout(8)
            assert exact(conn, 1) == b"\x05"
            exact(conn, exact(conn, 1)[0])
            conn.sendall(b"\x05\x00")
            version, command, reserved = exact(conn, 3)
            assert version == 5 and reserved == 0
            address(conn, allow_unspecified=command == 3)
            if command == 1:
                conn.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
                while not self.closed.is_set():
                    data = conn.recv(1024)
                    if not data:
                        break
                    conn.sendall(self.label + b":" + data)
            elif command == 3:
                udp = bound(socket.SOCK_DGRAM)
                self.sockets.append(udp)
                conn.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", udp.getsockname()[1]))
                while not self.closed.is_set():
                    try:
                        packet, peer = udp.recvfrom(65535)
                    except socket.timeout:
                        continue
                    assert packet[:8] == b"\x00\x00\x00\x01\x7f\x00\x00\x01"
                    udp.sendto(packet[:10] + self.label + b":" + packet[10:], peer)
            else:
                raise AssertionError("Unexpected SOCKS fixture command")
        except (EOFError, OSError):
            pass
        finally:
            conn.close()

    def close(self):
        self.closed.set()
        for sock in self.sockets:
            sock.close()


def checked_runtime(portable, engine):
    lock_name = "xray-core" if engine == "xray" else engine
    lock = json.loads((ROOT / "engine" / f"{lock_name}.lock.json").read_text(encoding="utf-8"))
    directory = portable / ("engine" if engine == "sing-box" else "xray")
    for record in lock["runtimeFiles"]:
        if record["kind"] not in ("executable", "library"):
            continue
        file = directory / record["path"]
        assert hashlib.sha256(file.read_bytes()).hexdigest() == record["sha256"], "Pinned runtime integrity mismatch"
    return directory / f"{engine}.exe"


def api(port, method, selector, index=None, token="a" * 48):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    try:
        body = None if index is None else json.dumps({"name": f"node-{index}"})
        conn.request(method, f"/proxies/{selector}", body, {"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
        response = conn.getresponse()
        return response.status, response.read(128 * 1024)
    finally:
        conn.close()


def tcp_client(port):
    conn = socket.create_connection(("127.0.0.1", port), timeout=3)
    conn.sendall(b"\x05\x01\x00")
    assert exact(conn, 2) == b"\x05\x00"
    conn.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01\x20\xfb")
    assert exact(conn, 3) == b"\x05\x00\x00"
    address(conn)
    return conn


def udp_client(port):
    control = socket.create_connection(("127.0.0.1", port), timeout=3)
    control.sendall(b"\x05\x01\x00")
    assert exact(control, 2) == b"\x05\x00"
    control.sendall(b"\x05\x03\x00\x01\x7f\x00\x00\x01\x00\x00")
    assert exact(control, 3) == b"\x05\x00\x00"
    endpoint = address(control, allow_unspecified=True)
    return control, bound(socket.SOCK_DGRAM), endpoint


def tcp_roundtrip(conn, expected):
    conn.sendall(b"fixture")
    assert exact(conn, len(expected) + 8) == expected + b":fixture"


def udp_roundtrip(client, expected):
    _, sock, endpoint = client
    sock.sendto(b"\x00\x00\x00\x01\x7f\x00\x00\x01\x20\xfbfixture", endpoint)
    packet, _ = sock.recvfrom(1024)
    assert packet[10:] == expected + b":fixture", repr(packet)


def stop_child(child):
    if child.poll() is None:
        child.terminate()
        child.wait(timeout=5)


def main():
    args = argparse.ArgumentParser(description=__doc__)
    args.add_argument("--runtime-root", type=Path, required=True)
    args.add_argument("--generated-dir", type=Path)
    options = args.parse_args()
    engine = checked_runtime(options.runtime_root, "sing-box")
    hidden = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
    if options.generated_dir:
        xray = checked_runtime(options.runtime_root, "xray")
        for command in ([str(engine), "check", "-c", str(options.generated_dir / "sing-box.json")],
                        [str(xray), "run", "-test", "-config", str(options.generated_dir / "xray.json")]):
            checked = subprocess.run(command, capture_output=True, timeout=20, creationflags=hidden)
            assert checked.returncode == 0, checked.stderr.decode(errors="replace")
        print("PASS: Rust-generated multi-profile TUN and Xray configurations accepted (check only)")
    a, b = SocksFixture(b"A"), SocksFixture(b"B")
    reservations = [bound() for _ in range(3)]
    ingress, candidate, control = [sock.getsockname()[1] for sock in reservations]
    selectors = [{"type":"selector", "tag":tag, "outbounds":["node-0","node-1"],
                  "default":"node-0", "interrupt_exist_connections":False} for tag in ("selected","candidate")]
    config = {"log":{"level":"error"},
              "inbounds":[{"type":"socks","tag":tag,"listen":"127.0.0.1","listen_port":port}
                          for tag,port in (("socks-in",ingress),("candidate-in",candidate))],
              "outbounds":selectors + [{"type":"socks","tag":f"node-{i}","server":"127.0.0.1","server_port":fixture.port}
                                       for i,fixture in enumerate((a,b))],
              "route":{"rules":[{"inbound":["candidate-in"],"action":"route","outbound":"candidate"}],"final":"selected"},
              "experimental":{"clash_api":{"external_controller":f"127.0.0.1:{control}","secret":"a"*48,
                              "access_control_allow_origin":["http://routedeck.invalid"],"access_control_allow_private_network":False}}}
    child = None
    clients = []
    try:
        with tempfile.TemporaryDirectory(prefix="routedeck-switch-fixture-") as temp, contextlib.ExitStack() as processes:
            path = Path(temp)/"fixture.json"
            path.write_text(json.dumps(config), encoding="utf-8")
            for reservation in reservations:
                reservation.close()
            with (Path(temp)/"engine.log").open("wb") as log:
                child = subprocess.Popen([str(engine),"run","-c",str(path)], stdout=log, stderr=log, creationflags=hidden)
                processes.callback(stop_child, child)
                deadline = time.monotonic()+8
                while True:
                    assert child.poll() is None, "Fixture engine exited"
                    try:
                        if api(control,"GET","selected")[0] == 200:
                            break
                    except OSError:
                        pass
                    assert time.monotonic() < deadline, "Fixture engine readiness timeout"
                    time.sleep(.05)
                assert api(control,"PUT","selected",1,token="wrong")[0] == 401
                old_tcp = tcp_client(ingress); clients.append(old_tcp)
                old_udp = udp_client(ingress); clients.extend(old_udp[:2])
                tcp_roundtrip(old_tcp,b"A"); udp_roundtrip(old_udp,b"A")
                assert api(control,"PUT","candidate",1)[0] == 204
                candidate_tcp = tcp_client(candidate); clients.append(candidate_tcp)
                tcp_roundtrip(candidate_tcp,b"B")
                assert json.loads(api(control,"GET","selected")[1])["now"] == "node-0"
                tcp_roundtrip(old_tcp,b"A"); udp_roundtrip(old_udp,b"A")
                assert api(control,"PUT","selected",1)[0] == 204
                assert json.loads(api(control,"GET","selected")[1])["now"] == "node-1"
                tcp_roundtrip(old_tcp,b"A"); udp_roundtrip(old_udp,b"A")
                new_tcp = tcp_client(ingress); clients.append(new_tcp)
                new_udp = udp_client(ingress); clients.extend(new_udp[:2])
                tcp_roundtrip(new_tcp,b"B"); udp_roundtrip(new_udp,b"B")
                assert api(control,"PUT","selected",0)[0] == 204
                tcp_roundtrip(old_tcp,b"A"); udp_roundtrip(old_udp,b"A")
                tcp_roundtrip(new_tcp,b"B"); udp_roundtrip(new_udp,b"B")
                assert child.poll() is None
                print("PASS: authenticated candidate check, unchanged selected exit during check, new TCP/UDP on new exit, old TCP/UDP retained across both switches")
    finally:
        for client in clients:
            client.close()
        if child and child.poll() is None:
            child.terminate()
            child.wait(timeout=5)
        a.close(); b.close()


if __name__ == "__main__":
    main()
