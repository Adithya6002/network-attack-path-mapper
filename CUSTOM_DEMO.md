# 15-Minute Live Validation With Your Own Firewall Rules

**Goal:** invent a firewall policy on the spot, ask the tool to predict every connection, enforce the same policy on the real router, measure real traffic, and show that prediction = reality.

**Before you start:** all 4 VMs running and logged in (router: `adithya`, web/db: `labdb`, kali: `kali`), a terminal open in Kali, and PowerShell open in the project folder on Windows.

---

## Step 1: Choose the rules (minutes 0–2)

Decide two or three rules, or let the reviewer choose. Example (already saved as `data/firewall_custom.json`):

| # | From | To | Ports | Action |
|---|---|---|---|---|
| 1 | user-lan `10.10.10.0/24` | web `10.10.20.10/32` | 22, 8080 | allow |
| 2 | web `10.10.20.10/32` | db `10.10.30.20/32` | 22, 5432 | allow |
| – | everything else | | | deny |

The hosts are:
- kali **10.10.10.5**;
- web **10.10.20.10** (listens on 22, 80, 443);
- db **10.10.30.20** (listens on 22, 5432).

Allowing a port where nothing listens (like 8080 on web) gives a **refused** result, which tests the model in a different way.

## Step 2: Write the rules for the tool (minutes 2–4, Windows)

Open `data/firewall_custom.json` in VS Code and edit the `rules` list. Keep `"proto": "tcp"` on each rule, which keeps the router commands short.

```json
{"action": "allow", "src": "10.10.10.0/24", "dst": "10.10.20.10/32", "ports": [22, 8080], "proto": "tcp"}
```

## Step 3: Get the model's prediction (minute 4–5, Windows)

```bash
.\.venv\Scripts\python main.py predict --firewall data/firewall_custom.json
```

The output is grouped **by source VM** (kali, web, db), in exactly the order `measure.sh` will print. Keep this window visible.

**Say:** "The tool has now predicted all 36 connections before anything is changed on the network."

## Step 4: Get the router commands (minute 5, Windows)

```bash
.\.venv\Scripts\python lab\json_to_iptables.py data\firewall_custom.json
```

This prints the exact iptables rules for your policy, from the same file the tool just used.

## Step 5: Load the rules on the router (minutes 5–9, lab-router)

Type these, copying each `-s ... -j ACCEPT` line from Step 4 (one per rule):

```bash
sudo iptables -F FORWARD
```
```bash
sudo iptables -P FORWARD DROP
```
```bash
sudo iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
```
```bash
sudo iptables -A FORWARD -s 10.10.10.0/24 -d 10.10.20.10/32 -p tcp -m multiport --dports 22,8080 -j ACCEPT
```
```bash
sudo iptables -A FORWARD -s 10.10.20.10/32 -d 10.10.30.20/32 -p tcp -m multiport --dports 22,5432 -j ACCEPT
```

Check them:
```bash
sudo iptables -L FORWARD -n --line-numbers
```

**Say:**
- the first command clears the old rules;
- the second sets "block by default";
- the third allows replies;
- each following line is one of my rules, identical to the tool's input.

(The generated script also has two lines blocking the router's internet adapter. That adapter is unplugged, so they can be skipped here.)

## Step 6: Measure reality (minutes 9–13, kali + web + db)

Run this in **each** of the three VMs at the same time (each takes up to about 40 seconds):

```bash
bash ~/measure.sh custom
```

Each prints 12 lines like `custom,10.10.10.5,10.10.20.10,22,open`:
- **open** = connected;
- **refused** = allowed by the firewall, but nothing listening;
- **timeout** = blocked by the firewall.

## Step 7: Compare (minutes 13–15)

Go row by row: Kali's output against the **"From kali"** block from Step 3, then web against "From web", then db against "From db". Every line should match.

**For the example policy, the 4 non-timeout results to point at:**

| Connection | Predicted | Why |
|---|---|---|
| kali → web :22 | open | rule 1 allows it, web listens on 22 |
| kali → web :8080 | refused | rule 1 allows it, but nothing listens on 8080 |
| web → db :22 | open | rule 2 allows it, db listens on 22 |
| web → db :5432 | open | rule 2 allows it, db listens on 5432 |

Everything else: **timeout** (default deny).

**Say:** "The model predicted all 36 connections before the rules were applied, and the real network matched every one. That's the same validation as the recorded 72/72, repeated live with rules chosen just now."

---

## After the demo (lab-router)

Restore the normal policy:
```bash
sudo firewall-baseline.sh
```

## If a row doesn't match

| Symptom | Likely cause |
|---|---|
| Everything times out, even allowed rows | A typo in the router rule (check `sudo iptables -L FORWARD -n`) |
| An allowed row says `refused` where you expected `open` | That service isn't running on the VM (check with `ss -tln` there) |
| web/db rows all time out | That VM hasn't finished booting; wait for its login prompt |
| `measure.sh: No such file` | Run it from the home folder: `bash ~/measure.sh custom` |
