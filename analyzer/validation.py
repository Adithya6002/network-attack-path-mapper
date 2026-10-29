"""Validate the IPv4/TCP/UDP model before building graphs or shell scripts."""

import ipaddress

ANY = (None, "any", "*")


def ipv4(value, context="IP address", network=False):
    if not isinstance(value, str):
        raise ValueError(f"{context} must be an IPv4 string.")
    try:
        parsed = ipaddress.ip_network(value, strict=False) if network else ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError(f"{context}: invalid IPv4 address or CIDR {value!r}.") from exc
    if parsed.version != 4:
        raise ValueError(f"{context}: only IPv4 is supported.")
    return parsed


def validate_port(port, context="port"):
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError(f"{context} must be an integer from 1 to 65535.")


def validate_firewall(firewall, context="firewall"):
    if not isinstance(firewall, dict):
        raise ValueError(f"{context} must be an object.")
    unknown = set(firewall) - {"default", "rules", "description"}
    if unknown:
        raise ValueError(f"{context}: unknown fields {sorted(unknown)}.")
    if firewall.get("default") not in ("allow", "deny"):
        raise ValueError(f"{context}.default must explicitly be 'allow' or 'deny'.")
    rules = firewall.get("rules", [])
    if not isinstance(rules, list):
        raise ValueError(f"{context}.rules must be a list.")
    for i, rule in enumerate(rules, 1):
        where = f"{context} rule {i}"
        if not isinstance(rule, dict):
            raise ValueError(f"{where} must be an object.")
        unknown = set(rule) - {"action", "src", "dst", "ports", "proto", "description"}
        if unknown:
            raise ValueError(f"{where}: unknown fields {sorted(unknown)}.")
        if rule.get("action") not in ("allow", "deny"):
            raise ValueError(f"{where}.action must be 'allow' or 'deny'.")
        for field in ("src", "dst"):
            if rule.get(field) not in ANY:
                ipv4(rule[field], f"{where}.{field}", network=True)
        if rule.get("proto", "any") not in ("tcp", "udp", "any"):
            raise ValueError(f"{where}.proto must be 'tcp', 'udp' or 'any'.")
        ports = rule.get("ports")
        if ports not in ANY:
            if not isinstance(ports, list) or not ports:
                raise ValueError(f"{where}.ports must be a nonempty list or 'any'.")
            for port in ports:
                validate_port(port, f"{where}.ports")
            if len(set(ports)) != len(ports):
                raise ValueError(f"{where}.ports contains duplicates.")


def validate_network(network, firewall=None):
    if not isinstance(network, dict):
        raise ValueError("Network data must be an object.")
    hosts, subnets = network.get("hosts"), network.get("subnets")
    if not isinstance(hosts, list) or not isinstance(subnets, list):
        raise ValueError("Network hosts and subnets must be lists.")
    validate_firewall(firewall if firewall is not None else network.get("firewall"))
    warnings = network.get("model_warnings", [])
    if not isinstance(warnings, list) or not all(isinstance(w, str) for w in warnings):
        raise ValueError("model_warnings must be a list of strings.")
    names, ranges = set(), []
    for i, subnet in enumerate(subnets, 1):
        if not isinstance(subnet, dict):
            raise ValueError(f"Subnet {i} must be an object.")
        name = subnet.get("name")
        if not isinstance(name, str) or not name.strip() or name == "unknown":
            raise ValueError(f"Subnet {i} needs a nonempty name other than 'unknown'.")
        if name in names:
            raise ValueError(f"Duplicate subnet name {name!r}.")
        names.add(name)
        net = ipv4(subnet.get("cidr"), f"Subnet {name}.cidr", network=True)
        if any(net.overlaps(other) for other in ranges):
            raise ValueError(f"Subnet {name} overlaps another subnet.")
        ranges.append(net)
    ips = set()
    for i, host in enumerate(hosts, 1):
        if not isinstance(host, dict):
            raise ValueError(f"Host {i} must be an object.")
        addr = ipv4(host.get("ip"), f"Host {i}.ip")
        if addr in ips:
            raise ValueError(f"Duplicate host IP {addr}.")
        ips.add(addr)
        if ranges and not any(addr in net for net in ranges):
            raise ValueError(f"Host {addr} is outside the declared subnets.")
        if type(host.get("critical", False)) is not bool:
            raise ValueError(f"Host {addr}.critical must be a boolean.")
        for field in ("hostname", "os", "role"):
            if not isinstance(host.get(field, ""), str):
                raise ValueError(f"Host {addr}.{field} must be a string.")
        ports = host.get("ports", [])
        if not isinstance(ports, list):
            raise ValueError(f"Host {addr}.ports must be a list.")
        services = set()
        for service in ports:
            if not isinstance(service, dict):
                raise ValueError(f"Host {addr}: each service must be an object.")
            validate_port(service.get("port"), f"Host {addr} port")
            proto = service.get("proto", "tcp")
            if proto not in ("tcp", "udp"):
                raise ValueError(f"Host {addr}: service protocol must be tcp or udp.")
            for field in ("service", "product"):
                if not isinstance(service.get(field, ""), str):
                    raise ValueError(f"Host {addr}: {field} must be a string.")
            key = (service["port"], proto)
            if key in services:
                raise ValueError(f"Host {addr}: duplicate service {key}.")
            services.add(key)
        if "firewall" in host:
            validate_firewall(host["firewall"], f"Host {addr} inbound firewall")
