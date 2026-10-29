"""Measure a 12-endpoint, four-subnet Linux namespace lab using real sockets.

Root command: python3 lab/namespace_lab.py run --out evidence/namespace_lab
The router has no uplink. All interfaces and firewall changes live in newly
created namespaces, which are deleted in finally. Listener labels describe
test endpoints, not real SSH/HTTP/PostgreSQL application implementations.
"""

import argparse
import copy
import csv
import errno
import hashlib
import json
import os
import platform
import select
import selectors
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from lab.json_to_iptables import rule_lines  # noqa: E402

PROBES = [(22, "tcp"), (8080, "tcp"), (8443, "tcp"), (5432, "tcp"), (5353, "udp")]


def scenarios():
    hosts, subnets = [], []
    for zone, third, service in (("users", 10, None), ("dmz", 20, 8080), ("app", 30, 8443), ("data", 40, 5432)):
        subnets.append({"name": zone, "cidr": f"10.44.{third}.0/24"})
        for index in range(1, 4):
            ports = [{"port": 22, "proto": "tcp", "service": "test-tcp"},
                     {"port": 5353, "proto": "udp", "service": "test-udp-echo"}]
            if service:
                ports.append({"port": service, "proto": "tcp", "service": "test-tcp"})
            hosts.append({"ip": f"10.44.{third}.{10 + index}", "hostname": f"{zone}{index}",
                          "role": zone, "critical": zone == "data", "ports": ports})
    flat = {"subnets": subnets, "hosts": hosts, "firewall": {"default": "allow", "rules": []}}
    segmented = copy.deepcopy(flat)
    segmented["firewall"] = {"default": "deny", "rules": [
        {"action": "allow", "src": "10.44.10.0/24", "dst": "10.44.20.0/24", "ports": [8080], "proto": "tcp"},
        {"action": "allow", "src": "10.44.20.0/24", "dst": "10.44.30.0/24", "ports": [8443], "proto": "tcp"},
        {"action": "allow", "src": "10.44.30.0/24", "dst": "10.44.40.0/24", "ports": [5432], "proto": "tcp"},
        {"action": "allow", "src": "10.44.10.0/24", "dst": "10.44.20.0/24", "ports": [5353], "proto": "udp"},
        {"action": "allow", "src": "10.44.30.0/24", "dst": "10.44.40.0/24", "ports": [5353], "proto": "udp"},
    ]}
    hardened = copy.deepcopy(segmented)
    for host in hardened["hosts"]:
        if host["role"] == "data":
            host["firewall"] = {"default": "deny", "rules": [
                {"action": "allow", "src": "10.44.30.0/24", "ports": [5432], "proto": "tcp"},
                {"action": "allow", "src": "10.44.30.0/24", "ports": [5353], "proto": "udp"},
            ]}
    return {"flat": flat, "segmented": segmented, "hardened": hardened}


def command(args, check=True):
    return subprocess.run(args, capture_output=True, text=True, check=check, timeout=30)


class NamespaceLab:
    def __init__(self):
        self.prefix = "napm-" + uuid.uuid4().hex[:8]
        self.router = self.prefix + "-r"
        self.created, self.servers = [], []
        self.host_ns = {}

    def inside(self, namespace, *args, check=True):
        if namespace not in self.created:
            raise ValueError("Only namespaces created by this lab can be changed.")
        return command(["ip", "netns", "exec", namespace, *args], check=check)

    def add_namespace(self, name):
        command(["ip", "netns", "add", name])
        self.created.append(name)
        self.inside(name, "ip", "link", "set", "lo", "up")

    def setup(self, network):
        self.add_namespace(self.router)
        self.inside(self.router, "sysctl", "-w", "net.ipv4.ip_forward=1")
        bridge_nf = self.inside(self.router, "sysctl", "-n", "net.bridge.bridge-nf-call-iptables", check=False)
        if bridge_nf.returncode == 0:
            self.inside(self.router, "sysctl", "-w", "net.bridge.bridge-nf-call-iptables=0")
        for subnet in network["subnets"]:
            bridge = "br-" + subnet["name"]
            self.inside(self.router, "ip", "link", "add", bridge, "type", "bridge")
            gateway = subnet["cidr"].replace("0/24", "1/24")
            self.inside(self.router, "ip", "addr", "add", gateway, "dev", bridge)
            self.inside(self.router, "ip", "link", "set", bridge, "up")
        for index, host in enumerate(network["hosts"]):
            namespace = self.prefix + "-" + str(index)
            self.add_namespace(namespace)
            self.host_ns[host["ip"]] = namespace
            router_port = f"v{index}"
            self.inside(self.router, "ip", "link", "add", router_port, "type", "veth", "peer", "name", "eth0", "netns", namespace)
            self.inside(self.router, "ip", "link", "set", router_port, "master", "br-" + host["role"])
            self.inside(self.router, "ip", "link", "set", router_port, "up")
            self.inside(namespace, "ip", "addr", "add", host["ip"] + "/24", "dev", "eth0")
            self.inside(namespace, "ip", "link", "set", "eth0", "up")
            gateway = host["ip"].rsplit(".", 1)[0] + ".1"
            self.inside(namespace, "ip", "route", "add", "default", "via", gateway)
            encoded = json.dumps(host["ports"])
            server = subprocess.Popen(["ip", "netns", "exec", namespace, sys.executable, "-u", str(Path(__file__).resolve()),
                                       "_serve", "--ports", encoded], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.servers.append(server)
            ready, _, _ = select.select([server.stdout], [], [], 10)
            if not ready or server.stdout.readline().strip() != "READY":
                raise RuntimeError(f"Listener failed in {namespace}.")

    def apply_policy(self, network):
        for namespace in self.created:
            self.inside(namespace, "conntrack", "-F")
        self.apply_firewall(self.router, "FORWARD", network["firewall"])
        for host in network["hosts"]:
            self.apply_firewall(self.host_ns[host["ip"]], "INPUT", host.get("firewall", {"default": "allow", "rules": []}))

    def apply_firewall(self, namespace, chain, policy):
        self.inside(namespace, "iptables", "-P", chain, "DROP")
        self.inside(namespace, "iptables", "-F", chain)
        self.inside(namespace, "iptables", "-A", chain, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT")
        for rule in policy["rules"]:
            for line in rule_lines(rule):
                args = shlex.split(line)
                args[2] = chain
                self.inside(namespace, *args)
        self.inside(namespace, "iptables", "-P", chain, "ACCEPT" if policy["default"] == "allow" else "DROP")

    def snapshot(self, out, label):
        folder = out / "snapshots"
        folder.mkdir(exist_ok=True)
        for namespace in self.created:
            parts = [f"namespace: {namespace}\n"]
            for args in (("ip", "-4", "addr"), ("ip", "-4", "route"), ("iptables-save",)):
                parts.append("$ " + " ".join(args) + "\n" + self.inside(namespace, *args).stdout)
            (folder / f"{label}-{namespace}.txt").write_text("\n".join(parts), encoding="utf-8")

    def close(self):
        for process in self.servers:
            if process.poll() is None:
                process.terminate()
        for process in self.servers:
            try:
                process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()
        for namespace in reversed(self.created):
            command(["ip", "netns", "del", namespace], check=False)


def serve(ports):
    selector = selectors.DefaultSelector()
    for service in ports:
        proto = service.get("proto", "tcp")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if proto == "udp" else socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", service["port"]))
        if proto == "tcp":
            sock.listen(128)
        sock.setblocking(False)
        selector.register(sock, selectors.EVENT_READ, proto)
    print("READY", flush=True)
    while True:
        for key, _ in selector.select():
            if key.data == "udp":
                data, source = key.fileobj.recvfrom(2048)
                key.fileobj.sendto(data, source)
            else:
                connection, _ = key.fileobj.accept()
                connection.close()


def probe(destination, port, proto, timeout):
    began = time.perf_counter()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM if proto == "udp" else socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((destination, port))
            if proto == "udp":
                token = uuid.uuid4().bytes
                sock.send(token)
                if sock.recv(2048) != token:
                    raise ValueError("UDP echo token mismatch")
        result, detail = "open", ""
    except (TimeoutError, socket.timeout):
        result, detail = "timeout", ""
    except OSError as exc:
        result = "refused" if exc.errno == errno.ECONNREFUSED else "error"
        detail = str(exc)
    return {"destination": destination, "port": port, "proto": proto,
            "result": result, "detail": detail, "duration_s": round(time.perf_counter() - began, 4)}


def run(out, timeout):
    if sys.platform != "linux" or os.geteuid() != 0:
        raise ValueError("Run this command as root in Linux/WSL2, not Windows Python.")
    for executable in ("ip", "iptables", "iptables-save", "conntrack", "sysctl"):
        if shutil.which(executable) is None:
            raise ValueError(f"Missing {executable}; install iproute2 iptables conntrack first.")
    if out.exists():
        raise ValueError("Choose a new output directory to preserve earlier evidence.")
    networks = scenarios()
    out.mkdir(parents=True)
    for label, network in networks.items():
        (out / f"{label}.json").write_text(json.dumps(network, indent=2), encoding="utf-8")
    manifest = {"created_utc": datetime.now(timezone.utc).isoformat(), "platform": platform.platform(),
                "endpoints": 12, "subnets": 4, "policies": list(networks), "probes": PROBES,
                "timeout_s": timeout, "expected_rows": 12 * 11 * len(PROBES) * len(networks),
                "listener_type": "Generic TCP listeners and UDP echo, not application protocol servers",
                "lab_type": "Linux network namespaces sharing one kernel; not independent VMs",
                "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), "completed": False}
    lab = NamespaceLab()
    manifest["namespace_prefix"] = lab.prefix
    try:
        lab.setup(networks["flat"])
        with (out / "measurements.csv").open("w", newline="", encoding="utf-8") as stream:
            fields = ["policy", "source", "destination", "port", "proto", "result", "detail", "duration_s"]
            writer = csv.DictWriter(stream, fieldnames=fields)
            writer.writeheader()
            for label, network in networks.items():
                lab.apply_policy(network)
                lab.snapshot(out, label)
                for host in network["hosts"]:
                    destinations = [h["ip"] for h in network["hosts"] if h["ip"] != host["ip"]]
                    result = lab.inside(lab.host_ns[host["ip"]], sys.executable, str(Path(__file__).resolve()), "_probe",
                                        "--destinations", json.dumps(destinations), "--timeout", str(timeout))
                    for row in json.loads(result.stdout):
                        writer.writerow(dict(row, policy=label, source=host["ip"]))
                    stream.flush()
                    print(f"{label}: measured from {host['hostname']} ({host['ip']})", flush=True)
        manifest["completed"] = True
    finally:
        lab.close()
        manifest["cleanup_attempted"] = True
        (out / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"Measurements saved: {out}. Run lab/validate_namespace.py to compare with the model.")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("run", "_serve", "_probe"))
    parser.add_argument("--out", type=Path, default=ROOT / "evidence/namespace_lab_2026-10-28")
    parser.add_argument("--timeout", type=float, default=1)
    parser.add_argument("--ports")
    parser.add_argument("--destinations")
    args = parser.parse_args(argv)
    if not 0 < args.timeout <= 10:
        parser.error("Timeout must be between zero and ten seconds.")
    if args.command == "_serve":
        serve(json.loads(args.ports))
    elif args.command == "_probe":
        cases = [(dst, port, proto) for dst in json.loads(args.destinations) for port, proto in PROBES]
        with ThreadPoolExecutor(max_workers=16) as pool:
            results = list(pool.map(lambda case: probe(*case, args.timeout), cases))
        print(json.dumps(results))
    else:
        run(args.out.resolve(), args.timeout)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError, RuntimeError) as exc:
        sys.exit(f"Lab failed: {exc}")
