# Network Attack Path Mapper: Team Brief

A short overview of the project for team members. For full details see [PROJECT.md](PROJECT.md); for likely review questions see [REVIEW_NOTES.md](REVIEW_NOTES.md).

## What the project does

If an intruder takes over one computer in a network, how far can they spread? This tool answers that question.

It takes three inputs:

- **hosts** (computers and their IP addresses);
- **open services** on each host (for example SSH on port 22, a web server on 80/443, a database on 5432);
- **firewall rules** between subnets.

From these it builds a **graph**: each computer is a node, and an arrow from A to B means "A can connect to a service on B". It then reports:

- which hosts can be reached, and in how many steps (hops);
- bounded shortest-first routes to critical servers, with truncation indicated;
- **choke points**: hosts that every route must pass through, which are the best places to defend;
- what changes when the firewall policy changes.

The tool shows **reachability only**. It does not test whether a host can actually be broken into.

## Key networking ideas

- **Different subnets:** traffic goes through the router, where the firewall checks its rules in order and the first match decides.
- **Same subnet:** traffic bypasses the router firewall. The implemented inbound host-firewall policy can still block it.
- **Allowed connections chain together.** Each rule can look harmless on its own, but together they can form a route to a critical server. That's what the tool is built to find.

## Results so far

| Area | Result |
|---|---|
| **Sample network** (7 hosts, 3 subnets) | Stricter firewall: connections **34 → 12**, routes to the database **50+ → 2**, database **1 → 2 hops** (only through the web server). The file server stays reachable because it shares a subnet with the database. |
| **Real lab** (4 virtual machines, real iptables firewall) | The tool's predictions matched **72 of 72** measured connections (95% confidence interval: 95.0–100%). |
| **Expanded Linux lab** | **1,980/1,980** TCP/UDP observations matched across 12 endpoint namespaces, four subnets and three policies. Includes host-inbound controls; namespaces share one kernel. |
| **Larger synthetic benchmarks** | 500, 1,000 and 2,000 hosts, four policies and three timing repeats; current times/memory are in `experiments/results/large_2026-10-28/summary.md`. Earlier 360-run comparisons use reimplemented baselines and this model as reference. |
| **Code quality** | **115 automated tests**, all passing. `review_demo.ps1` prepares the review; `lab/NAMESPACE_LAB.md` and benchmark commands reproduce new evidence separately. |

**Status: TRL 3.** The idea is proven on paper and in a real lab.

## What is new (novelty)

1. Finds **multi-hop** exposure, not only direct connections.
2. Models **traffic inside subnets**, including optional inbound host-firewall controls.
3. **Validated on a real network:** the same policy file drives both the tool and the lab firewall.
4. Compares modeled approaches on fixed synthetic networks, with limitations stated; the graph algorithms themselves are established methods.
5. Finds **choke points** to show where to defend first.

## Project layout

| Folder / file | Contents |
|---|---|
| `analyzer/` | Graph building, route search, choke points |
| `collector/` | Reads Nmap scan results |
| `visualization/` | Interactive network pictures (HTML) |
| `data/` | Sample network, lab network, firewall policies |
| `lab/` | Lab setup guide and scripts |
| `evidence/` | Lab measurements and screenshots |
| `experiments/` | Large-scale tests, results and charts |
| `tests/` | Automated tests |
| `main.py` | Command-line entry point |

## How to run it (Windows PowerShell)

From the project folder:

```bash
.\.venv\Scripts\python main.py compare --start 10.10.10.5 --after data/firewall_segmented.json
```

Then open `output\comparison.html` for synchronized before/after panels. For the complete course demonstration, run `.\review_demo.ps1` and follow `FINAL_REVIEW.md`.

**Reading the pictures:**

- red star = starting host;
- orange diamonds = critical servers;
- dashed line = crosses the firewall;
- solid line = inside one subnet;
- thick red line = part of a route to a critical server.

## Next steps

- Rehearse the working demo, capture the updated evidence, and finish the actual presentation using `FINAL_REVIEW.md`.
- An advisory single-connection recommender is implemented. Coordinated changes and a globally minimum cut remain future work.
- An independent operator and a second platform/multi-VM rerun would strengthen the new namespace evidence.
