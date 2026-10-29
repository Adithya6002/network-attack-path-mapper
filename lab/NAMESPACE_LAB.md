# Expanded real-connection lab

This lab measures 12 endpoint network namespaces plus an isolated router namespace across four subnets: users, DMZ, application and data. Each subnet has three endpoints. It exercises real Linux routing, bridges, iptables, TCP handshakes and UDP echo.

Namespaces share one kernel. This is a larger connectivity experiment, not 12 independent VMs or a test of application vulnerabilities. TCP listeners simulate service ports; they do not implement SSH, HTTPS or PostgreSQL.

## What it measures

Every endpoint probes every other endpoint on TCP 22, 8080, 8443 and 5432, and a known UDP echo listener on 5353. There are three policies:

1. **Flat:** routed traffic allowed; same-subnet traffic stays local.
2. **Segmented:** users → DMZ on 8080; DMZ → app on 8443; app → data on 5432. UDP is allowed for users → DMZ and app → data only. Other routed traffic is dropped.
3. **Hardened:** segmented network policy plus inbound host firewalls on data endpoints. App → data database and UDP echo connections remain allowed; other new inbound data connections are blocked, including local-subnet traffic.

Expected coverage: **12 × 11 × 5 × 3 = 1,980 measured connections**. The report checks firewall decisions separately from listening-service reachability. A test infrastructure error is not silently counted as a denied connection. Missing and duplicate observations fail validation.

## Run from this Windows workspace using Ubuntu WSL

Install the Linux dependencies once:

```powershell
wsl -d Ubuntu -u root --exec apt-get update
wsl -d Ubuntu -u root --exec apt-get install -y --no-install-recommends iptables conntrack
```

Run a new measurement set. Choose a new output directory for each run; previous evidence is never overwritten:

```powershell
wsl -d Ubuntu -u root --exec python3 /mnt/d/Projects/network-attack-path-mapper/lab/namespace_lab.py run --out /mnt/d/Projects/network-attack-path-mapper/evidence/namespace_lab_repeat
```

Compare those observed outcomes with the model using the project virtual environment:

```powershell
.\.venv\Scripts\python lab/validate_namespace.py evidence/namespace_lab_repeat
```

On a Linux VM, from its project directory, use `sudo python3 lab/namespace_lab.py run --out evidence/namespace_lab_repeat`, then run the validator with the Python environment containing the project dependencies.

## Evidence to retain

- `measurements.csv`: every observed connection, result, error detail and duration.
- `flat.json`, `segmented.json`, `hardened.json`: the exact modeled/deployed inputs.
- `manifest.json`: platform, script fingerprint, namespace prefix, planned coverage and completion status.
- `snapshots/`: addresses, routes and firewall rules for every namespace under each policy.
- `validation.md` and `validation.json`: generated comparison and model analyses.

The script creates uniquely named `napm-*` namespaces. It adds only virtual interfaces inside them, creates no router uplink, and applies firewall and forwarding settings inside the new namespaces. Listener processes and namespaces are cleaned up in a `finally` block. Do not interrupt it with a forced machine shutdown.

The model is driven by the same JSON as the deployed rules, so this validates their agreement with real socket behavior under these scenarios. Repeated probes on one kernel are correlated; do not claim universal accuracy or automatically upgrade the project's TRL.

## References

- [Linux ip-netns manual](https://man7.org/linux/man-pages/man8/ip-netns.8.html): namespace network stacks and cleanup behavior.
- [Linux bridge documentation](https://www.kernel.org/doc/html/latest/networking/bridge.html): bridging and bridge netfilter hooks. Bridge filtering is disabled within the router namespace so same-subnet bridging follows the model's assumptions.
