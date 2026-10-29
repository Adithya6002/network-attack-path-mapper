"""Synthetic enterprise networks and firewall policies for the scale experiments.

A network has five zone types - user, dmz, app, data, mgmt - each split into
one or more /24 subnets. Hosts get services typical of their zone, chosen with
a seeded random generator so every run is reproducible. Every data-zone host
is marked critical.
"""

import random

ZONES = ("user", "dmz", "app", "data", "mgmt")
# Share of hosts per zone.
ZONE_SHARE = {"user": 0.45, "dmz": 0.10, "app": 0.20, "data": 0.15, "mgmt": 0.10}
# (port, service, probability) per zone.
ZONE_SERVICES = {
    "user": [(445, "microsoft-ds", 0.6), (3389, "ms-wbt-server", 0.3), (22, "ssh", 0.1)],
    "dmz": [(80, "http", 1.0), (443, "https", 1.0), (22, "ssh", 0.8), (25, "smtp", 0.2)],
    "app": [(8080, "http-alt", 1.0), (22, "ssh", 0.9), (445, "microsoft-ds", 0.2)],
    # Data zone = database servers or file servers, chosen per host (see below).
    "data": [(22, "ssh", 0.9)],
    "mgmt": [(22, "ssh", 1.0), (3389, "ms-wbt-server", 0.5)],
}
DB_PORTS = [5432, 3306]


def generate_network(n_hosts, subnets_per_zone=1, seed=0, separate_fileservers=False):
    """Return a network dict in the same format as data/network.json.

    separate_fileservers=True puts databases in the first data subnet and file
    servers in the others (needs subnets_per_zone >= 2); otherwise they are mixed.
    """
    if type(n_hosts) is not int or n_hosts < 10:
        raise ValueError("At least 10 hosts are needed for five zones with two hosts each.")
    if type(subnets_per_zone) is not int or not 1 <= subnets_per_zone <= 16:
        raise ValueError("subnets_per_zone must be between 1 and 16 to avoid overlapping zone addresses.")
    if separate_fileservers and subnets_per_zone < 2:
        raise ValueError("Separating file servers requires at least two subnets per zone.")
    # Keep historical allocations when they sum correctly; adjust rounding for
    # other sizes so a requested host count is always the actual host count.
    counts = {zone: max(2, round(n_hosts * ZONE_SHARE[zone])) for zone in ZONES}
    while sum(counts.values()) != n_hosts:
        excess = sum(counts.values()) > n_hosts
        eligible = [zone for zone in ZONES if not excess or counts[zone] > 2]
        zone = max(eligible, key=lambda z: (counts[z] - n_hosts * ZONE_SHARE[z]) * (1 if excess else -1))
        counts[zone] += -1 if excess else 1
    if max(counts.values()) > subnets_per_zone * 240:
        raise ValueError("Requested hosts exceed subnet capacity; increase subnets_per_zone.")
    rng = random.Random(seed)
    subnets, hosts = [], []
    for z, zone in enumerate(ZONES):
        zone_hosts = counts[zone]
        per_subnet = -(-zone_hosts // subnets_per_zone)
        for s in range(subnets_per_zone):
            third = z * 16 + s
            cidr = f"10.{100 + seed % 100}.{third}.0/24"
            name = f"{zone}{s + 1}"
            subnets.append({"name": name, "cidr": cidr, "zone": zone})
            count = min(per_subnet, zone_hosts - s * per_subnet, 240)
            for i in range(max(count, 0)):
                ports = [
                    {"port": port, "proto": "tcp", "service": svc}
                    for port, svc, p in ZONE_SERVICES[zone]
                    if rng.random() < p
                ]
                role = zone
                if zone == "data":
                    is_db = (s == 0) if separate_fileservers else rng.random() < 0.6
                    if is_db:
                        role = "database"
                        db = rng.choice([(5432, "postgresql"), (3306, "mysql")])
                        ports.append({"port": db[0], "proto": "tcp", "service": db[1]})
                    else:
                        role = "fileserver"
                        ports.append({"port": 445, "proto": "tcp", "service": "microsoft-ds"})
                hosts.append({
                    "ip": cidr.replace("0/24", str(10 + i)),
                    "hostname": f"{name}-h{i + 1}",
                    "role": role,
                    "critical": zone == "data",
                    "ports": ports,
                })
    return {"subnets": subnets, "hosts": hosts, "firewall": {"default": "allow", "rules": []}}


def _zone_cidrs(network, zone):
    return [s["cidr"] for s in network["subnets"] if s["zone"] == zone]


def _rules(network, src_zone, dst_zone, ports, action="allow"):
    dst_cidrs = ["any"] if dst_zone == "any" else _zone_cidrs(network, dst_zone)
    return [
        {"action": action, "src": s, "dst": d, "ports": ports}
        for s in _zone_cidrs(network, src_zone)
        for d in dst_cidrs
    ]


def policies(network):
    """Four firewall configurations, from no segmentation to tiered + one misconfiguration."""
    r = lambda *a, **k: _rules(network, *a, **k)  # noqa: E731
    permissive = (
        r("user", "dmz", "any") + r("user", "app", [22, 445, 8080]) + r("dmz", "app", "any")
        + r("app", "data", "any") + r("mgmt", "any", "any") + r("data", "any", "any")
    )
    tiered = (
        r("user", "dmz", [80, 443]) + r("dmz", "app", [8080]) + r("app", "data", DB_PORTS)
        + r("mgmt", "dmz", [22]) + r("mgmt", "app", [22]) + r("mgmt", "data", [22])
    )
    # A common misconfiguration: users allowed RDP to the management (jump) hosts.
    # No rule lets users reach the data zone, yet mgmt can SSH into it.
    misconfig = r("user", "mgmt", [3389]) + tiered
    return {
        "flat": {"default": "allow", "rules": []},
        "permissive": {"default": "deny", "rules": permissive},
        "tiered": {"default": "deny", "rules": tiered},
        "tiered+misconfig": {"default": "deny", "rules": misconfig},
    }
