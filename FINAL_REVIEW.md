# Final course review: preparation checklist

The remaining work is evidence packaging, demonstration practice and presentation. The graph engine, policy validation, host-inbound firewalls, service comparison, offline dashboard and advisory recommender are implemented.

## Evidence you can demonstrate

| Evidence | What it supports | Where |
|---|---|---|
| Automated test suite | Regression coverage of modeled semantics and tooling; not proof of real-network accuracy | `tests/` |
| Original 4-VM, 72-connection TCP experiment | Model agreement in that recorded VM lab | `evidence/validation_results.md` |
| New 12-endpoint, 4-subnet, 3-policy TCP/UDP experiment | Model agreement with 1,980 observed socket connections, including host firewalls | `evidence/namespace_lab_2026-10-28/validation.md` |
| Repeated synthetic benchmarks at 500, 1,000 and 2,000 hosts | Time and memory scaling for the measured generated topologies | `experiments/results/large_2026-10-28/summary.md` |
| Earlier 360 synthetic comparison runs | Differences from the reimplemented scan/rule/zone baselines, relative to this model | `experiments/results/summary.md` |

The namespace experiment uses one WSL Linux kernel and generic TCP listeners/UDP echo. It is not twelve VMs, real application testing, exploit validation, or an automatic TRL upgrade. The 1,980 connections are 1,980 observations, each checked against firewall and service predictions; do not double that observation count.

The repeated scale test uses one seed and three timing repeats per size/policy. Its runtime variation is not a confidence interval over all enterprise networks. The machine is an ordinary desktop with background activity; use recorded medians, ranges and environment metadata, rather than claiming a universal speed limit.

## Recorded outcome (28 Oct 2026)

- **115 automated tests passed.** The complete `review_demo.ps1` run succeeded; its transcript is `output/final_review_demo.txt`.
- **1,980/1,980** expanded-lab observations matched both modeled checks, with zero mismatched observations. Namespace cleanup was verified after measurement.
- **36/36** synthetic timing cases completed within the configured resource budgets: three sizes × four policies × three repeats.
- At **2,000 hosts**, median build-plus-analysis times were **59.96 s flat**, **86.62 s permissive**, **83.82 s tiered**, and **102.76 s tiered+misconfig**. The dense flat case had 3,536,231 edges and used up to **1,534.2 MiB** peak worker memory.
- The benchmark used Windows/Python 3.12 with 16 logical CPUs and approximately 32 GiB RAM. Ordinary desktop activity and some concurrent lab/test preparation were present; these are practical measurements, not a controlled performance certification.

## What you should do, in order

1. **Run the demonstration once yourself:** `.\review_demo.ps1`. It rechecks tests and recorded lab evidence and generates sample/host-firewall dashboards. It does not run the lengthy scalability benchmark or recreate namespaces.
2. **Practice the five-minute explanation:** problem → graph model → sample segmentation → measured validation → scaling/limitations. Explain that each intermediate host must be assumed compromised before its outgoing connections become attacker options.
3. **Prepare presentation evidence:** captures of the database path and host-firewall service changes are already in `output/final_review/screenshots/`. Add a terminal capture of the expanded validator and the new `scalability.png`. Keep the original VM screenshot as a separate earlier experiment.
4. **Update the actual presentation:** use `PPT_PROMPT.md` as the revised outline. Replace old test counts and runtime claims with the current recorded evidence. Add your actual team members, contributions and course details yourself.
5. **Prepare a backup:** save the generated HTML, PNG, JSON and CSV evidence locally. The HTML reports work offline. Demonstrate the small graph live; show the larger run's saved results instead of spending minutes computing it during the review.
6. **Review and freeze the submission:** inspect the Git diff, commit the intended code/evidence, and record that final revision in your submitted report. Do not present uncommitted implementation work as an already published release.

## Suggested live demonstration

1. Show `output/final_review/sample/comparison.html`. Point out 34 → 12 directed connections, database distance 1 → 2, and web as the mandatory intermediate host. The six other hosts remain potentially reachable.
2. Select the database and one path. Explain the service/first-match firewall reason for each connection. Graph hops count potential pivots, not physical router hops.
3. Show `output/final_review/host_firewalls/comparison.html`. Explain the measured 51 → 45 connection change and the loss of local data-host connections. Required app → database services remain permitted.
4. Show `evidence/namespace_lab_2026-10-28/validation.md`: coverage, TCP versus UDP results, and zero mismatches. Open a raw measurement row and its saved firewall snapshot.
5. Show `experiments/results/large_2026-10-28/scalability.png` beside its summary. Explain build time, analysis time, memory use and the four-hop/50-path cap. Read the actual final values rather than memorizing the older under-15-second figure.
6. Show one recommendation. State that it blocks one directed host pair, is evaluated independently, preserves declared direct business flows, and is not guaranteed to be the smallest combined fix.

## Prepare to explain these points

- A directed edge contains one or more allowed destination services; it is not an exploit.
- An open service does not prove compromise. A multi-hop path assumes control of intermediate hosts.
- Router firewalls govern routed traffic; host-inbound policies can also govern local-subnet traffic.
- Reachability uses BFS; path enumeration is bounded; choke points use dominators; centrality measures a different property and is sampled for larger graphs.
- Fewer graph edges need not mean fewer reachable critical assets. Service exposure and shortest-path distances can change while host reachability stays the same.
- Larger synthetic tests measure scaling; the namespace and VM tests check observed connectivity in specific labs.
- One scan location cannot supply a complete whole-network service inventory. Imported scans still need policy and critical-asset metadata.
- The contribution is the implemented, explainable workflow and measured evaluation. The graph algorithms themselves are established methods.

## Further engineering after this review

An independent operator rerun, a second operating-system/router environment, real application services, and a larger multi-VM topology would strengthen external validation. A port-specific or coordinated-change recommender would go beyond the current single-connection heuristic. Those are future extensions; the final demonstration can focus on the working prototype and its measured limits.
