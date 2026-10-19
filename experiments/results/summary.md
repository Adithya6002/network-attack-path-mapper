# Experiment summary

Comparison runs: 360 (designs ['mixed', 'separated'], sizes [100, 250, 500], seeds [0, 1, 2], 5 start hosts each, 4 policies).

## Critical hosts exposed: tool vs. common approaches (mean per run)

| Design | Policy | Critical total | Tool: exposed | (file servers) | within 2 hops | min hops | Scan: seen / missed | Direct rule review: flagged / missed | Zone review: flagged / false alarms |
|---|---|---|---|---|---|---|---|---|---|
| mixed | flat | 42.7 | 42.7 | 17.3 | 42.7 | 1.0 | 42.7 / 0.0 | 42.7 / 0.0 | 42.7 / 0.0 |
| mixed | permissive | 42.7 | 42.7 | 17.3 | 42.7 | 2.0 | 0.0 / 42.7 | 0.0 / 42.7 | 42.7 / 0.0 |
| mixed | tiered | 42.7 | 42.7 | 17.3 | 0.0 | 3.0 | 0.0 / 42.7 | 0.0 / 42.7 | 42.7 / 0.0 |
| mixed | tiered+misconfig | 42.7 | 42.7 | 17.3 | 38.4 | 2.0 | 0.0 / 42.7 | 0.0 / 42.7 | 42.7 / 0.0 |
| separated | flat | 42.7 | 42.7 | 21.0 | 42.7 | 1.0 | 42.7 / 0.0 | 42.7 / 0.0 | 42.7 / 0.0 |
| separated | permissive | 42.7 | 42.7 | 21.0 | 42.7 | 2.0 | 0.0 / 42.7 | 0.0 / 42.7 | 42.7 / 0.0 |
| separated | tiered | 42.7 | 21.7 | 0.0 | 0.0 | 3.0 | 0.0 / 21.7 | 0.0 / 21.7 | 42.7 / 21.0 |
| separated | tiered+misconfig | 42.7 | 42.7 | 21.0 | 37.8 | 2.0 | 0.0 / 42.7 | 0.0 / 42.7 | 42.7 / 0.0 |

## Running time (seed 0)

| Hosts | Policy | Edges | Build (s) | Analyze (s) | Total (s) |
|---|---|---|---|---|---|
| 50 | flat | 2058 | 0.006 | 0.013 | 0.019 |
| 50 | permissive | 1181 | 0.008 | 0.007 | 0.015 |
| 50 | tiered | 515 | 0.007 | 0.004 | 0.011 |
| 50 | tiered+misconfig | 603 | 0.008 | 0.004 | 0.012 |
| 100 | flat | 8415 | 0.015 | 0.044 | 0.059 |
| 100 | permissive | 4815 | 0.03 | 0.031 | 0.061 |
| 100 | tiered | 2223 | 0.029 | 0.014 | 0.043 |
| 100 | tiered+misconfig | 2493 | 0.032 | 0.016 | 0.049 |
| 250 | flat | 55029 | 0.172 | 0.275 | 0.447 |
| 250 | permissive | 31463 | 0.183 | 0.194 | 0.377 |
| 250 | tiered | 14600 | 0.202 | 0.068 | 0.27 |
| 250 | tiered+misconfig | 15832 | 0.233 | 0.079 | 0.312 |
| 500 | flat | 221057 | 0.527 | 1.027 | 1.554 |
| 500 | permissive | 126332 | 0.903 | 0.796 | 1.698 |
| 500 | tiered | 60170 | 0.69 | 0.3 | 0.99 |
| 500 | tiered+misconfig | 66245 | 0.913 | 0.396 | 1.31 |
| 1000 | flat | 887112 | 2.416 | 3.762 | 6.179 |
| 1000 | permissive | 456630 | 8.323 | 2.761 | 11.084 |
| 1000 | tiered | 180458 | 9.288 | 1.21 | 10.499 |
| 1000 | tiered+misconfig | 202058 | 11.081 | 1.738 | 12.819 |

## Policy changes (250 hosts, mean over seeds)

| Change | Edges | Reachable hosts | Critical reachable |
|---|---|---|---|
| flat -> permissive | 55859 -> 31856 | 224 -> 224 | 38 -> 38 |
| permissive -> tiered+misconfig | 31856 -> 16119 | 224 -> 181 | 38 -> 38 |
| tiered+misconfig -> tiered | 16119 -> 14850 | 181 -> 156 | 38 -> 38 |
