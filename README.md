# Network Attack Path Mapper

**Graph-Based Analysis of Potential Attack Paths in Computer Networks**

This tool models how an attacker who already has a foothold on one host could move through a network. It turns Nmap results, subnet definitions and firewall rules into a directed graph using NetworkX. It then reports multi-hop paths, choke points and key intermediate hosts, and draws the graph with PyVis.

> **Limitation:** results are **network reachability paths**, not confirmed exploit paths. An open, reachable port does not prove that the host can be compromised.

## Results at a glance (TRL 3)

| Evidence | Result |
|---|---|
| Lab validation (4 VMs, real iptables router, 2 policies) | **72/72** measured connections matched the model; 95% CI for accuracy 95.0%–100% |
| Comparison on simulated 100–500-host networks (360 runs) | Reimplemented scan/direct-review baselines miss multi-hop exposure in the segmented scenarios; the zone baseline over-reports separated file servers relative to this model |
| Expanded real-connection lab | **1,980/1,980** observations matched: 12 Linux endpoint namespaces, 4 subnets, 3 policies, TCP/UDP and host-inbound controls; one shared kernel |
| Scalability | Repeated measurements at 500, 1,000 and 2,000 hosts, including time, memory and resource limits; see [current benchmark](experiments/results/large_2026-10-28/summary.md) |
| Automated tests | **116** passing, including input validation, scan boundaries, host firewalls, prediction integration and evidence tooling |

Full write-up: **[PROJECT.md](PROJECT.md)**. To regenerate every number and figure, run `.\reproduce.ps1` (about 5 minutes; needs no VMs).

For the final course review, follow **[FINAL_REVIEW.md](FINAL_REVIEW.md)** and run `.\review_demo.ps1`. The original reproduction script reruns the historical experiment suite; the new larger tests are separate so earlier evidence stays intact.

Repeat the larger synthetic benchmark with a new output directory:

```powershell
.\.venv\Scripts\python -m experiments.benchmark_large --sizes 500 1000 2000 --repeats 3 --out experiments/results/large_repeat
.\.venv\Scripts\python -m experiments.plot_large experiments/results/large_repeat
```

Each case runs in a separate process with a default 180-second timeout and a monitored 2,048 MiB memory budget. Results include raw runs, timing medians/ranges, input hashes and environment metadata. These measurements include sampled centrality and a four-hop/50-path cap, not exhaustive all-path enumeration.

For observed connectivity on the larger Linux lab, see **[lab/NAMESPACE_LAB.md](lab/NAMESPACE_LAB.md)**. Recheck the saved observations with:

```powershell
.\.venv\Scripts\python lab/validate_namespace.py evidence/namespace_lab_2026-10-28
```

## How the graph is built

- **Nodes** are hosts: IP, hostname, OS, subnet and open services.
- **Edge A → B** means at least one open service on B is reachable from A.
  - If A and B are in the **same subnet** (same L2 segment), the traffic bypasses the router firewall. An optional inbound host firewall on B still applies.
  - If they are in **different subnets**, the traffic is routed through the firewall. Rules are checked in order and the first match wins. Traffic that matches no rule gets the `default` policy.
- **Analysis** (run from a chosen start host):
  - Reachable hosts and the minimum hop count to each.
  - Up to 50 shortest-first simple paths to hosts marked `"critical": true`, within `--max-hops`. Reports explicitly indicate when additional paths were omitted.
  - **Choke points**, found with dominator-tree analysis. A choke point is a host that every path must pass through to reach certain other hosts.
  - **Key nodes**, ranked by betweenness centrality.
  - A **before/after comparison**, including added/removed services and the rules responsible even when hosts remain reachable.
  - Independent **remediation simulations** that preserve declared business connections.

## Setup (Windows PowerShell)

Run every command from inside the project folder. In PowerShell, a program in the current folder must start with `.\`.

Use **Python 3.12**. Dependency versions are pinned; `requirements-lock.txt` records the complete tested Windows environment. Platform-specific dependencies may be added by pip on Linux. CI checks Python 3.12 on Windows and Linux.

```powershell
cd "D:\Projects\network-attack-path-mapper"
```

```bash
py -m venv .venv
```

```bash
.\.venv\Scripts\python -m pip install -r requirements-lock.txt
```

On Kali/Ubuntu, use `python3 -m venv .venv`, then `.venv/bin/pip install -r requirements-lock.txt`. You can also activate the Windows environment with `.\.venv\Scripts\Activate.ps1`; activation is optional when using the explicit Python path.

## Usage

Analyse the sample lab from the Kali foothold:

```bash
.\.venv\Scripts\python main.py analyze --start 10.10.10.5
```

Simulate network segmentation and compare (this writes an offline `output/comparison.html` dashboard plus `before.html` and `after.html`):

```bash
.\.venv\Scripts\python main.py compare --start 10.10.10.5 --after data/firewall_segmented.json
```

The dashboard synchronizes subnet, service and critical-target filters. Select a target and path to inspect each connection's policy explanation. Reports embed their graph libraries and work offline. At most 1,500 connections are displayed by default; `--max-visual-edges` changes that display budget without limiting the analysis. Filters operate on the displayed subset.

`--after` also accepts a complete network JSON file, so you can compare host-firewall, inventory, and subnet changes as well as network firewall rules.

Export structured analysis and explanations, or compare service changes without generating HTML:

```powershell
.\.venv\Scripts\python main.py analyze --start 10.10.10.5 --explain --json output/analysis.json --no-html
.\.venv\Scripts\python main.py compare --start 10.10.10.5 --after data/firewall_segmented.json --json output/comparison.json --no-html
```

Rank suggested connection blocks while preserving the example HTTPS and database business flows:

```powershell
.\.venv\Scripts\python main.py recommend --start 10.10.10.5 --required data/required_connections.json --json output/recommendations.json
```

Each suggestion is an **independent simulation**, blocking all services from one source host to one destination. Suggestions specify whether to prepend the deny rule to the network firewall or the destination's inbound host firewall. They are never applied automatically. The search evaluates at most 200 candidates (`--max-candidates`) and returns up to five (`--limit`). It ranks reductions in reachable critical hosts, then increases in minimum hops. It does not compute a globally optimal cut, and a redundant network may need several coordinated changes before exposure falls.

Use `recommend --firewall data/firewall_segmented.json ...` to evaluate an alternate network policy first.

`--required` takes a JSON list of `{ "source": "10.10.20.10", "destination": "10.10.30.20", "port": 5432, "proto": "tcp" }`. These direct service connections must already be allowed. Undeclared application dependencies are not protected; customize this file for your network.

Scan your own isolated VirtualBox lab (run this inside Kali; only IPv4 RFC1918 and loopback ranges are accepted):

```bash
python3 main.py scan --targets 192.168.56.0/24 --out data/lab.json
```

Or parse a scan you already saved with `nmap -sV -oX scan.xml ...`:

```bash
python3 main.py scan --targets 192.168.56.0/24 --xml scan.xml --out data/lab.json
```

After scanning, edit `data/lab.json`:

- give each subnet a name;
- add `firewall` rules;
- mark important hosts with `"critical": true`.

Then run `analyze --data data/lab.json --start <kali-ip>`.

Scanned inventories include visible assumption warnings: an Nmap scan only observes services from its scanning location, and its generated default-allow policy is a placeholder until you configure the real rules. The scanner accepts a restricted option set through `--nmap-args`, including `-sV`, `-sT`, `-sS`, `-sU`, `-Pn`, `-n`, `-T0`–`-T5`, `-p`, `-p-`, `--top-ports`, version-detection options, `--open`, `--reason`, `-v`, `-vv`, `--max-retries`, and `--host-timeout`. Additional targets, input files, scripts and output overrides are rejected. `--scan-timeout` bounds the entire process (300 seconds by default).

Run the tests:

```bash
.\.venv\Scripts\python -m pytest
```

## Data format

```json
{
  "subnets": [{"name": "dmz", "cidr": "10.10.20.0/24"}],
  "hosts": [{"ip": "10.10.20.10", "hostname": "web", "critical": false,
             "ports": [{"port": 80, "proto": "tcp", "service": "http"}]}],
  "firewall": {"default": "deny", "rules": [
    {"action": "allow", "src": "10.10.10.0/24", "dst": "10.10.20.10/32", "ports": [80, 443]}
  ]}
}
```

In a rule, `src` and `dst` take a CIDR or `"any"`. `ports` takes a list of port numbers or `"any"`. `proto` is optional: `tcp`, `udp` or `any`.

Every firewall policy must explicitly specify `"default": "allow"` or `"deny"`. IPv6, overlapping subnets, duplicate subnet names/IPs/services, invalid ports, unknown policy fields and non-boolean critical flags are rejected with readable errors. Subnets represent separate L2 segments; hosts must belong to a declared subnet when subnets are provided.

To model a host's **inbound firewall**, add a `firewall` object to that host using the same rule format. For example:

```json
"firewall": {
  "default": "deny",
  "rules": [{"action": "allow", "src": "10.10.20.10/32", "ports": [5432], "proto": "tcp"}]
}
```

This allows database connections from the web server and blocks other inbound services, including traffic from hosts sharing the database subnet. Routed traffic must pass both the network and host policies. Host egress policies, multiple routers, overlapping address spaces, explicit VLAN topology and NAT are not modeled.

## Lab safety

- Keep Metasploitable and the other lab VMs on **Host-only** or **Internal** VirtualBox networks, never on Bridged or NAT.
- Scan only systems you own or have permission to test.
