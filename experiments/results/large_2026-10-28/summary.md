# Large synthetic-network benchmark

Synthetic scalability measurements; these are not real-host connectivity validation.

| Hosts | Policy | Completed / attempted | Median (s) | Min–max (s) | SD (s) | Peak memory (MiB) |
|---|---|---|---|---|---|---|
| 500 | flat | 3/3 | 3.18 | 2.71–3.19 | 0.28 | 133.7 |
| 500 | permissive | 3/3 | 3.61 | 3.40–3.63 | 0.13 | 89.3 |
| 500 | tiered | 3/3 | 3.01 | 2.83–3.40 | 0.29 | 58.9 |
| 500 | tiered+misconfig | 3/3 | 3.24 | 3.21–3.37 | 0.08 | 61.3 |
| 1000 | flat | 3/3 | 12.99 | 10.56–13.21 | 1.47 | 414.8 |
| 1000 | permissive | 3/3 | 21.71 | 19.91–22.78 | 1.45 | 241.7 |
| 1000 | tiered | 3/3 | 21.49 | 20.70–22.37 | 0.84 | 119.1 |
| 1000 | tiered+misconfig | 3/3 | 26.50 | 24.88–27.43 | 1.29 | 127.8 |
| 2000 | flat | 3/3 | 59.96 | 58.19–60.55 | 1.23 | 1534.2 |
| 2000 | permissive | 3/3 | 86.62 | 84.72–87.63 | 1.48 | 838.6 |
| 2000 | tiered | 3/3 | 83.82 | 83.76–85.15 | 0.79 | 351.8 |
| 2000 | tiered+misconfig | 3/3 | 102.76 | 100.96–107.09 | 3.15 | 390.1 |

Completed: 36/36 cases. Resource-limited or failed cases: 0.

Timing includes graph building and full analyze() (reachability, capped paths, dominators, centrality).
Process startup, input generation, hashing, and JSON printing are excluded from total_s; wall_s includes them.
Centrality is sampled above 64 hosts; critical paths are capped at 50 per target within four hops.
Memory covers the worker interpreter, generated inventory, graph, and analysis; units are MiB (2^20 bytes).
Successful workers report native peak working set (Windows) or peak RSS (Unix); failed workers report sampled process-tree RSS.
Resource enforcement samples the worker and any launcher children every 100 ms; limits may be briefly exceeded between samples.
Repeated runs with one seed measure timing variation for one topology, not variation across network designs.
The generator uses at least four /24 subnets per zone and adds capacity for larger sizes; subnet/rule counts are recorded.
