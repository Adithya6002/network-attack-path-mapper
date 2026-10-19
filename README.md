# Network Attack Path Mapper

**Graph-Based Analysis of Potential Attack Paths in Computer Networks**

This tool models how an attacker who already has a foothold on one host could move through a network. It turns Nmap results, subnet definitions and firewall rules into a directed graph using NetworkX. It then reports multi-hop paths, choke points and key intermediate hosts, and draws the graph with PyVis.

> **Limitation:** results are **network reachability paths**, not confirmed exploit paths. An open, reachable port does not prove that the host can be compromised.

## Results at a glance (TRL 3)

| Evidence | Result |
|---|---|
| Lab validation (4 VMs, real iptables router, 2 policies) | **72/72** measured connections matched the model; 95% CI for accuracy 95.0%–100% |
| Comparison on simulated 100–500-host networks (360 runs) | Scans and direct rule reviews miss **100%** of multi-hop exposure; zone-level reviews give **49%** false alarms and can't detect an RDP-to-management misconfiguration |
| Scalability | 1,000 hosts analysed in **≤ 14 s** under every policy |
| Automated tests | **41** passing |

Full write-up: **[PROJECT.md](PROJECT.md)**. To regenerate every number and figure, run `.\reproduce.ps1` (about 5 minutes; needs no VMs).

## How the graph is built

- **Nodes** are hosts: IP, hostname, OS, subnet and open services.
- **Edge A → B** means at least one open service on B is reachable from A.
  - If A and B are in the **same subnet** (same L2 segment), the traffic does not pass the firewall, so every open port on B counts.
  - If they are in **different subnets**, the traffic is routed through the firewall. Rules are checked in order and the first match wins. Traffic that matches no rule gets the `default` policy.
- **Analysis** (run from a chosen start host):
  - Reachable hosts and the minimum hop count to each.
  - All simple paths to hosts marked `"critical": true`, up to `--max-hops`.
  - **Choke points**, found with dominator-tree analysis. A choke point is a host that every path must pass through to reach certain other hosts.
  - **Key nodes**, ranked by betweenness centrality.
  - A **before/after comparison** for a simulated firewall or segmentation change.

## Setup (Windows PowerShell)

Run every command from inside the project folder. In PowerShell, a program in the current folder must start with `.\`.

```bash
cd "C:\Users\Adith\cn proj\network-attack-path-mapper"
```

```bash
py -m venv .venv
```

```bash
.\.venv\Scripts\python -m pip install -r requirements.txt
```

On Kali/Ubuntu, use `python3 -m venv .venv`, then `.venv/bin/pip install -r requirements.txt`.

## Usage

Analyse the sample lab from the Kali foothold:

```bash
.\.venv\Scripts\python main.py analyze --start 10.10.10.5
```

Simulate network segmentation and compare (this writes `output/before.html` and `output/after.html`):

```bash
.\.venv\Scripts\python main.py compare --start 10.10.10.5 --after data/firewall_segmented.json
```

Scan your own isolated VirtualBox lab (run this inside Kali; only private ranges are accepted):

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

## Lab safety

- Keep Metasploitable and the other lab VMs on **Host-only** or **Internal** VirtualBox networks, never on Bridged or NAT.
- Scan only systems you own or have permission to test.
