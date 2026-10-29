# Review Preparation: Network Attack Path Mapper

## 1. 60-second introduction

> "Our project is the Network Attack Path Mapper. Firewall rules are usually checked one at a time, so nobody sees how allowed connections chain together. If an intruder takes over one computer, our tool shows how far they can spread.
>
> It reads the hosts, their open ports, the subnets and the firewall rules, and builds a graph: each computer is a node, and an arrow means 'this host can connect to a service on that host'. From the graph it finds the routes to critical servers, the choke points every route must pass through, and what a firewall change would fix, before the change is applied.
>
> We validated it on a real network of four virtual machines whose router used the same policy file as the tool. All 72 measured connections matched the predictions, which is at least 95% accuracy at 95% confidence. In simulations of up to 1,000 hosts, it caught multi-hop exposure that network scans and rule-by-rule reviews missed."

## 2. Architecture in one line each

| Stage | What happens | Code |
|---|---|---|
| Input | Hosts, open ports, subnets, firewall rules (JSON, or from an Nmap scan) | `data/*.json`, `collector/` |
| Model | One arrow per host pair if any service gets through: same subnet = yes; else the first matching firewall rule decides | `analyzer/graph.py` |
| Analysis | BFS hops; routes to critical hosts; choke points (dominator tree); key hosts (betweenness); before/after diff | `analyzer/paths.py` |
| Output | Terminal report and interactive HTML graphs | `main.py`, `visualization/` |
| Validation | Same policy file → iptables on the lab router → real connection tests → compared with predictions | `lab/` |

## 3. Key numbers

| What | Number |
|---|---|
| Sample network: connections | 34 → 12 after segmentation |
| Routes to the database | 50+ → 2 |
| Database distance | 1 hop → 2 hops (only via web) |
| Lab validation | 72 / 72 matched; 95% CI 95.0–100% |
| Simulation | 360 runs; scans missed 100% of multi-hop exposure; zone review 49% false alarms |
| Speed | 1,000 hosts in under 15 s; path search 217 s → 1.2 s |
| Tests | 42 automated tests |
| TRL | 3 |

## 4. 25 likely questions with short answers

**Concept**

1. **What problem does your project solve?** It shows how far an intrusion can spread through a firewall-segmented network, and what a firewall change would fix, before deploying it.
2. **What is an edge (arrow) in your graph?** Host A can open a TCP connection to at least one service on host B.
3. **How do you decide whether an edge exists?** Same subnet: always, because the traffic never reaches the firewall. Different subnets: the firewall rules are checked top to bottom, and the first match decides; otherwise the default (deny) applies.
4. **Why does same-subnet traffic bypass the firewall?** Hosts in one subnet talk through the switch (Layer 2). Only traffic between subnets is routed through the router, where the firewall sits.
5. **What is a choke point?** A host that every route to some target must pass through. We find it with a dominator tree.
6. **Why is a choke point useful?** Monitoring or hardening that one host protects every route behind it.
7. **What is a dashed vs. a solid line?** Dashed = crosses the firewall (a rule allowed it). Solid = inside one subnet (no firewall rule can block it).

**Comparison and novelty**

8. **How is it different from Nmap?** Nmap sees only one hop from where it runs. Our tool models the whole network and finds 2–3-hop routes; in our simulations a scan missed all of them.
9. **How is it different from firewall rule review?** Rule review looks at rules and zones, not at which hosts actually listen on which ports, and it doesn't follow chains of connections. In our tests zone-level review gave 49% false alarms and missed a misconfiguration.
10. **How is it different from MulVAL or attack-graph tools?** They need vulnerability data. We model reachability only, from hosts, services and rules, and we validated that layer against a real network.
11. **What is new in your work?** Not a new algorithm. It's the validated model (including traffic inside subnets), the method of driving the model and the real router from one policy file, and measuring how common approaches fail.
12. **Is it a research contribution or just tools combined?** The tools are standard. The contribution is the validated integration and the measured comparison with common practices; we rate the novelty as moderate and applied.

**Implementation**

13. **Why Python and NetworkX?** Fast development, and NetworkX provides tested graph algorithms (BFS, dominators, betweenness), so we didn't need to re-implement them.
14. **What algorithms did you use?** BFS (hops), a pruned shortest-first path search (routes), immediate dominators (choke points), Brandes betweenness (key hosts), and the Clopper–Pearson interval (accuracy).
15. **How did you make it fast?** The path search skips branches that can't reach the target within the hop limit, and searches shortest paths first: 217 s → 1.2 s on 1,000 hosts, with identical results (tested).

**Lab and validation**

16. **How are the VMs connected?** Three VirtualBox internal networks act as virtual switches. The router VM has a card on each and IP forwarding on; each host routes other subnets via the router.
17. **How do you prove traffic goes through the router?** Ping shows TTL 63 instead of 64: one router hop.
18. **How did you validate the model?** The same policy file generated the router's iptables rules. We made 72 real TCP connection attempts under two policies and compared them with predictions: all 72 matched.
19. **What do open / refused / timeout mean?** Open = connected. Refused = the firewall allowed it but nothing was listening. Timeout = the firewall dropped it.
20. **Why is 72/72 not "100% accurate"?** 72 tests can't prove perfection. The exact Clopper–Pearson interval says accuracy is at least 95% with 95% confidence.
21. **Why did you use Kali?** It's the standard security-lab machine; it represents the compromised workstation and runs the connection tests. It didn't attack anything.
22. **Is your lab safe?** Yes. Internal networks are isolated from the internet and the college network, and the internet adapters were unplugged during tests.

**Limitations and future work**

23. **What are the limitations?** Reachability is not proof of compromise. TCP only. One router, no host firewalls. Small lab (4 VMs). Simulated networks use the model as the reference.
24. **Why is the database still reachable after segmentation?** The website needs web → db on 5432, so a firewall can't block it. That residual risk is handled by hardening and monitoring web (the choke point) and securing the database.
25. **What would you do next?** A hardening recommender: compute the smallest firewall change that cuts every route to critical servers while keeping required traffic (a minimum cut). Then validate on a larger real network.

## 5. Troubleshooting during the demo

| Problem | Fix |
|---|---|
| VM freezes or login resets | Free memory: close browsers fully; keep ≥ 3 GB free. Power-cycle that VM. |
| Typing doesn't appear in a VM | Click inside its window (title "lab-… [Running]"); accept "keyboard capture" if asked |
| `sudo: command not found` for firewall scripts | You're in the wrong VM; they exist only on lab-router |
| `nc` hangs ~2 s then times out | That's a firewall block, the expected result for blocked ports |
| VM stuck at boot after `sys-kernel-config.mount` | Power it off and start it again |
| Anything fails live | Show `evidence\screenshots\` and run the Windows commands (`compare`, `predict`, `compare_results.py`) |
