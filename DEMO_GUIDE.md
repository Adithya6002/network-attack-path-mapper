# Demo Guide: From Start to Finish (about 15 minutes)

Each step lists **Do**, **See**, **Say** and **Why** (why this tool or command was used). This file replaces LIVE_DEMO.md and CUSTOM_DEMO.md for the review.

---

## Step 0: Setup before the review (10 minutes)

1. **Close every other app** (browsers, chat apps), **including background processes** (Chrome and Edge keep running after their windows close; end them in Task Manager). Keep only VirtualBox and one PowerShell window.
   - *Why:* the 4 VMs need about 4.5 GB of RAM. When free memory drops below about 3 GB, Windows pauses the VMs, their clocks jump, boots hang and logins reset.
2. **Run the start script** from the project folder:

   ```bash
   .\lab\start_lab.ps1
   ```

   It checks free memory, warns about browsers still running, and starts **lab-router → lab-web → lab-db → kali** one at a time.
   - *Why:* starting them together overloads VirtualBox's Hyper-V mode, which caused the boot hangs we saw.
3. **Log in:**
   - router: `adithya`;
   - web: `labdb`;
   - kali: `kali` / `kali`, then open a terminal.
   - **lab-db does not need a login.** Its services (SSH, PostgreSQL) start automatically at boot.
4. **On lab-router**, reset the firewall: `sudo firewall-baseline.sh`
5. **On Windows**, open PowerShell in the project folder: `cd "C:\Users\Adith\cn proj\network-attack-path-mapper"`

If a VM freezes at boot, power it off and start it again (VirtualBox → right-click → Stop → Power Off, then Start).

---

## Step 1: The problem (1 minute, no commands)

**Say:** "Firewall rules are checked one at a time, so nobody sees how allowed connections chain together. If an intruder gets one computer, my tool shows how far they can spread, through which routes and choke points, and what a firewall change would fix."

**Why this matters:** segmentation is a main defence against lateral movement. Rule-by-rule review can't see multi-hop routes.

---

## Step 2: The tool on its own (3 minutes, Windows)

**Do:** open `data/network.json` in VS Code. Point at `"subnets"`, one host's `"ports"`, and the `"firewall"` rules.
- **Say:** "This is the input: hosts, open services, subnets and ordered firewall rules."
- **Why JSON:** a simple, readable format. The tool can also build it from an Nmap scan (`collector/parser.py`).

**Do:**
```bash
.\.venv\Scripts\python main.py compare --start 10.10.10.5 --after data/firewall_segmented.json
```
- **See:** `Edges: 34 -> 12`, `Paths to critical db: 50+ -> 2`, choke points `web guards db`.
- **Say:** "Segmentation cut connections from 34 to 12. The database is now 2 hops away, only through the web server, so web is the choke point."
- **Why:**
  - **NetworkX** provides tested graph algorithms;
  - **BFS** gives the minimum hops;
  - the **dominator tree** finds hosts every route must cross, which is exactly what a choke point is.

**Do:** open `output\before.html` and `output\after.html`.
- **Say:**
  - dashed line = crosses the firewall;
  - solid line = same subnet, so the firewall can't block it;
  - red = route to a critical host.
- **Why PyVis:** it turns the graph into an interactive picture that anyone can read.

---

## Step 3: How the VMs are connected (1 minute, VirtualBox)

**Do:** VirtualBox → **lab-router → Settings → Network** → click Adapter 1, 2 and 3 (then Cancel).
- **See:** Internal Network `lab-user-lan`, `lab-dmz`, `lab-internal`.
- **Say:** "Each subnet is a VirtualBox internal network, a virtual switch. The router is plugged into all three, so it's the only path between subnets."
- **Why Internal Network:** it's isolated from the college network and the internet, so testing is safe. Bridged would expose the VMs on the real network.

---

## Step 4: The router (2 minutes, lab-router)

```bash
ip -br addr
```
- **See:** 10.10.10.1, 10.10.20.1, 10.10.30.1.
- **Why:** one gateway address per subnet.

```bash
sysctl net.ipv4.ip_forward
```
- **See:** `= 1`.
- **Why:** turns the Linux VM into a router that passes packets between subnets.

```bash
sudo iptables -L FORWARD -n --line-numbers
```
- **See:** the baseline rules, default DROP.
- **Say:** "Traffic between subnets passes through this FORWARD chain. Rules are checked top to bottom and the first match wins, the same logic my tool uses."
- **Why iptables:** it's the standard Linux packet filter. These rules were generated from the tool's own policy file (`lab/json_to_iptables.py`), so the model and the real router enforce identical rules.

---

## Step 5: A host reaching other subnets (1 minute, kali)

```bash
ip route
```
- **See:** `10.10.0.0/16 via 10.10.10.1`.
- **Why:** this tells Kali to send traffic for other subnets to the router.

```bash
ping -c 2 10.10.20.10
```
- **See:** replies with `ttl=63`.
- **Say:** "TTL started at 64 and dropped by one at the router, which proves the packet was routed."
- **Why ping/TTL:** a simple, standard proof of a router hop.

---

## Step 6: The problem, live (1 minute, kali)

```bash
nc -zv -w 2 10.10.30.20 22
```
- **See:** `succeeded` (open).
- **Say:** "Under the baseline policy, Kali can reach the database directly on SSH. That's the exposure."
- **Why nc:** netcat makes one TCP connection attempt. It shows **open** (connected), **refused** (the firewall let it through, but nothing is listening) or **timeout** (the firewall dropped it).

---

## Step 7: The tool predicts the change first (1 minute, Windows)

```bash
.\.venv\Scripts\python main.py predict --firewall data/firewall_segmented.json --sources 10.10.10.5 10.10.20.10
```
- **See:**
  - kali → db: all ports **timeout**;
  - kali → web: 80 and 443 **open**;
  - web → db: 5432 **open**.
- **Say:** "Before touching the network, the tool predicts what will happen."
- **Why predict first:** a prediction made **before** the change is a real test. If it were made afterwards, it could just copy the result.

---

## Step 8: Apply segmentation and check the prediction (2 minutes)

**On lab-router:**
```bash
sudo firewall-segmented.sh
```

**On kali:**
```bash
nc -zv -w 2 10.10.30.20 22
```
- **See:** times out (blocked).

```bash
nc -zv -w 2 10.10.20.10 80
```
- **See:** open (allowed).

**On lab-web:**
```bash
nc -zv -w 2 10.10.30.20 5432
```
- **See:** open (allowed).

**Say:** "Every result matches the prediction. Kali can no longer reach the database directly; the only route is Kali → web → database, which is exactly the route the graph showed."

**Optional, the full check:** run `bash ~/measure.sh live` on kali and on web. It tests 12 connections each, which you can compare line by line with Step 7.

---

## Step 9: The recorded proof (1 minute, Windows)

```bash
.\.venv\Scripts\python lab\compare_results.py data\lab.json evidence\measurements.csv
```
- **See:** 72 of 72 matched, 95% CI 95.0–100%.
- **Say:** "Earlier I recorded 72 connections under both policies. All 72 matched, so the model is at least 95% accurate with 95% confidence."
- **Why a confidence interval:** 100% on 72 tests isn't proof of perfection. The Clopper–Pearson interval states honestly what 72 tests can support.

---

## Step 10: Finish

**On lab-router**, restore: `sudo firewall-baseline.sh`

**Say:** "This is TRL 3: the model is proven on paper and confirmed on a real network. The next step is a recommender that suggests the smallest firewall change needed to protect critical servers."

Shut down: router, web and db with Stop → ACPI Shutdown; Kali with Stop → Power Off.

---

## Quick answers if asked "why did you use…"

| Tool / choice | Why |
|---|---|
| Python | Fast to develop; strong networking and graph libraries |
| NetworkX | Tested graph algorithms (BFS, dominators, centrality); no need to re-implement them |
| PyVis | Interactive graph pictures for the before/after comparison |
| VirtualBox internal networks | Isolated, free, and easy to wire into separate subnets |
| Ubuntu router + iptables | Standard Linux router and packet filter; the same first-match logic as the model |
| Kali Linux | Standard security-lab machine with networking tools preinstalled; represents the compromised host |
| nginx / PostgreSQL | Real services, so connections have something to reach |
| nc (netcat) | One clean TCP test per port: open, refused or timeout |
| One policy file for tool and router | Guarantees the model and the real network use identical rules, which makes the comparison fair |
| Dominator tree | The mathematical definition of "a host every route must pass through" |
| Clopper–Pearson interval | An honest statistical bound for 72 out of 72 correct |
