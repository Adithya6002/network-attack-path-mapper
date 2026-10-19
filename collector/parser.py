"""Convert Nmap XML output into the project's network.json format."""

import ipaddress
import xml.etree.ElementTree as ET


def parse_nmap_xml(xml_text):
    """Return a list of host dicts: ip, hostname, os, ports."""
    root = ET.fromstring(xml_text)
    hosts = []
    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue

        ip = None
        mac = None
        for addr in host.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr")
            elif addr.get("addrtype") == "mac":
                mac = addr.get("addr")
        if ip is None:
            continue

        hostname_el = host.find("hostnames/hostname")
        os_el = host.find("os/osmatch")

        ports = []
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = port.find("service")
            ports.append({
                "port": int(port.get("portid")),
                "proto": port.get("protocol", "tcp"),
                "service": service.get("name", "") if service is not None else "",
                "product": " ".join(
                    filter(None, [service.get("product"), service.get("version")])
                ) if service is not None else "",
            })

        hosts.append({
            "ip": ip,
            "hostname": hostname_el.get("name") if hostname_el is not None else "",
            "mac": mac or "",
            "os": os_el.get("name") if os_el is not None else "",
            "ports": ports,
        })
    return hosts


def build_network(hosts, subnets, routes=""):
    """Wrap parsed hosts into network.json. Firewall starts empty (default allow)."""
    subnet_entries = []
    for i, cidr in enumerate(subnets):
        net = ipaddress.ip_network(cidr, strict=False)
        subnet_entries.append({"name": f"subnet{i + 1}", "cidr": str(net)})
    return {
        "subnets": subnet_entries,
        "hosts": hosts,
        "firewall": {"default": "allow", "rules": []},
        "routes": routes,
    }
