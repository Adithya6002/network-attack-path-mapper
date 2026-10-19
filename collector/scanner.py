"""Run Nmap against an authorized lab range and collect local routing info."""

import ipaddress
import platform
import shutil
import subprocess

DEFAULT_NMAP_ARGS = ["-sV", "-T4", "--top-ports", "1000"]


def validate_targets(targets):
    """Allow only private/loopback ranges so the tool can't be pointed at the internet."""
    networks = []
    for target in targets:
        net = ipaddress.ip_network(target, strict=False)
        if not (net.is_private or net.is_loopback):
            raise ValueError(
                f"{target} is not a private range. Scan only your isolated lab network."
            )
        networks.append(net)
    return networks


def run_nmap(targets, extra_args=None, nmap_path="nmap"):
    """Scan the targets and return Nmap's XML output as a string."""
    validate_targets(targets)
    if shutil.which(nmap_path) is None:
        raise FileNotFoundError(
            "nmap not found. Install it (it ships with Kali) or pass --nmap-path."
        )
    args = extra_args if extra_args else DEFAULT_NMAP_ARGS
    cmd = [nmap_path, *args, "-oX", "-", *targets]
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    return result.stdout


def collect_routes():
    """Return the scanning machine's routing table as raw text (for the report)."""
    if platform.system() == "Windows":
        cmd = ["route", "print", "-4"]
    elif shutil.which("ip"):
        cmd = ["ip", "route"]
    else:
        cmd = ["netstat", "-rn"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return result.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""
