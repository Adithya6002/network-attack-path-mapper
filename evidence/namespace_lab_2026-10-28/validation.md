# Expanded Linux namespace lab validation

12 endpoint namespaces, 4 subnets, 3 policies; **1980 measured connections**.

These are real TCP handshakes and UDP echo probes on a single shared Linux kernel. TCP listeners simulate service ports; they do not implement SSH, HTTPS or PostgreSQL.
UDP probes target a known running echo listener; closed UDP ports are outside this experiment.

| Policy | Protocol | Check | Tests | TP | TN | FP | FN | Accuracy |
|---|---|---|---|---|---|---|---|---|
| flat | tcp | firewall | 528 | 528 | 0 | 0 | 0 | 100.0% |
| flat | tcp | service | 528 | 231 | 297 | 0 | 0 | 100.0% |
| flat | udp | firewall | 132 | 132 | 0 | 0 | 0 | 100.0% |
| flat | udp | service | 132 | 132 | 0 | 0 | 0 | 100.0% |
| segmented | tcp | firewall | 528 | 123 | 405 | 0 | 0 | 100.0% |
| segmented | tcp | service | 528 | 69 | 459 | 0 | 0 | 100.0% |
| segmented | udp | firewall | 132 | 42 | 90 | 0 | 0 | 100.0% |
| segmented | udp | service | 132 | 42 | 90 | 0 | 0 | 100.0% |
| hardened | tcp | firewall | 528 | 99 | 429 | 0 | 0 | 100.0% |
| hardened | tcp | service | 528 | 57 | 471 | 0 | 0 | 100.0% |
| hardened | udp | firewall | 132 | 36 | 96 | 0 | 0 | 100.0% |
| hardened | udp | service | 132 | 36 | 96 | 0 | 0 | 100.0% |

**Mismatched observations: 0/1980.**

All expected source/destination/port/protocol combinations were present exactly once; unknown/error observations are rejected.
This case study does not establish universal accuracy, independent operating-system behavior, exploitability or a TRL upgrade.
The same JSON specification drives the model and deployed rules; socket measurements are observed separately from model predictions.
Raw measurements, policy inputs, platform metadata, and interface/routing/firewall snapshots are retained in this directory.

| Policy | Graph edges | Reachable hosts from first user | Reachable critical assets | Min hops to critical asset |
|---|---|---|---|---|
| flat | 132 | 11 | 3 | 1 |
| segmented | 51 | 11 | 3 | 3 |
| hardened | 45 | 11 | 3 | 3 |
