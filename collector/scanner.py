"""Run Nmap against an authorized lab range and collect local routing info."""

import ipaddress
import platform
import re
import shutil
import subprocess

DEFAULT_NMAP_ARGS = ["-sV", "-T4", "--top-ports", "1000"]
LAB_RANGES = tuple(ipaddress.ip_network(cidr) for cidr in
                   ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"))
SAFE_FLAGS = {"-sV", "-sT", "-sS", "-sU", "-Pn", "-n", "--open", "--reason",
              "--version-light", "--version-all", "-v", "-vv", "-p-"}


def validate_nmap_args(args):
    """Accept a small option allowlist; targets and output options are never accepted."""
    if not isinstance(args, (list, tuple)) or not all(isinstance(a, str) for a in args):
        raise ValueError("Nmap options must be a list of strings.")
    result = []
    i = 0
    while i < len(args):
        option = args[i]
        i += 1
        if option in SAFE_FLAGS or re.fullmatch(r"-T[0-5]", option):
            result.append(option)
            continue
        if option.startswith("-p") and option != "-p":
            option, value = "-p", option[2:]
        elif option in ("-p", "--top-ports", "--version-intensity", "--max-retries", "--host-timeout"):
            if i >= len(args):
                raise ValueError(f"Missing value for Nmap option {option}.")
            value = args[i]
            i += 1
        else:
            raise ValueError(f"Unsupported Nmap option {option!r}; targets belong in --targets.")
        if option == "-p":
            valid = bool(re.fullmatch(r"(?:[TU]:)?[0-9]+(?:-[0-9]+)?(?:,(?:[TU]:)?[0-9]+(?:-[0-9]+)?)*", value))
            valid = valid and all(1 <= int(n) <= 65535 for n in re.findall(r"[0-9]+", value))
            if valid:
                valid = all(int(a) <= int(b) for a, b in re.findall(r"([0-9]+)-([0-9]+)", value))
        elif option == "--host-timeout":
            valid = bool(re.fullmatch(r"[1-9][0-9]*(?:ms|s|m|h)", value))
        else:
            bounds = {"--top-ports": (1, 65535), "--version-intensity": (0, 9), "--max-retries": (0, 10)}
            low, high = bounds[option]
            valid = bool(re.fullmatch(r"[0-9]+", value)) and low <= int(value) <= high
        if not valid:
            raise ValueError(f"Invalid value {value!r} for Nmap option {option}.")
        result.extend([option, value])
    return result


def validate_targets(targets):
    """Allow only IPv4 RFC1918/loopback networks, rather than all special addresses."""
    if not targets:
        raise ValueError("At least one lab target is required.")
    networks = []
    for target in targets:
        net = ipaddress.ip_network(target, strict=False)
        if net.version != 4 or not any(net.subnet_of(lab) for lab in LAB_RANGES):
            raise ValueError(
                f"{target} is not a private range. Scan only your isolated lab network."
            )
        networks.append(net)
    return networks


def run_nmap(targets, extra_args=None, nmap_path="nmap", timeout=300):
    """Scan the targets and return Nmap's XML output as a string."""
    targets = [str(net) for net in validate_targets(targets)]
    args = validate_nmap_args(extra_args if extra_args is not None else DEFAULT_NMAP_ARGS)
    if not isinstance(timeout, (int, float)) or not 0 < timeout < float("inf"):
        raise ValueError("Scan timeout must be a positive finite number of seconds.")
    if shutil.which(nmap_path) is None:
        raise FileNotFoundError(
            "nmap not found. Install it (it ships with Kali) or pass --nmap-path."
        )
    cmd = [nmap_path, *args, "-oX", "-", *targets]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise ValueError(f"Nmap scan timed out after {timeout:g} seconds.") from exc
    except subprocess.CalledProcessError as exc:
        raise ValueError(f"Nmap failed (exit {exc.returncode}): {(exc.stderr or '').strip()}") from exc
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
