# Live Demo: How the Lab Connections Work

About 10 minutes. Follow the parts in order. Commands go in the VM shown in the heading.

## Before the review (5 minutes)

1. Close Chrome, Brave and other heavy apps (the lab needs about 5 GB of RAM).
2. In VirtualBox, start **lab-router**, **lab-web**, **lab-db** and **kali** (group **cn-lab**). Wait about 2 minutes.
3. Log in to each:
   - router: `adithya`
   - web and db: `labdb`
   - kali: `kali` / `kali`
4. In Kali, open a terminal.

---

## Part A: The virtual cables (VirtualBox, about 1 min)

Open **lab-router → Settings → Network**. Click Adapter 1, 2 and 3:

| Adapter | Attached to | Name |
|---|---|---|
| 1 | Internal Network | `lab-user-lan` |
| 2 | Internal Network | `lab-dmz` |
| 3 | Internal Network | `lab-internal` |

Then show kali (`lab-user-lan`), lab-web (`lab-dmz`) and lab-db (`lab-internal`).

**Say:** "Each internal network is a virtual switch. The router is plugged into all three, so it is the only path between the subnets. The internet adapters are unplugged, so the lab is isolated."

---

## Part B: The router (lab-router, about 2 min)

```bash
ip -br addr
```
Shows **10.10.10.1**, **10.10.20.1** and **10.10.30.1**: one IP in each subnet.

```bash
sysctl net.ipv4.ip_forward
```
Shows `= 1`: **routing is on**, so the router passes packets between subnets.

```bash
sudo iptables -L FORWARD -n --line-numbers
```
Shows the **baseline** firewall rules that control every connection between subnets.

**Say:** "All traffic between subnets goes through this router, and these iptables rules decide what is allowed."

---

## Part C: A host and its route (kali, about 2 min)

```bash
ip -br addr
```
Kali is **10.10.10.5** (user-lan).

```bash
ip route
```
Shows `10.10.0.0/16 via 10.10.10.1`: **other subnets are reached through the router**.

```bash
ping -c 2 10.10.10.1
```
Reaches the router directly, **TTL 64**.

```bash
ping -c 2 10.10.20.10
```
Reaches web in another subnet, **TTL 63**. **Say:** "The TTL dropped by one, which proves the packet passed through the router."

---

## Part D: Connections under the baseline policy (kali, about 1 min)

```bash
nc -zv -w 2 10.10.30.20 22
```
**open**: under the baseline policy Kali can reach the database directly, which is the problem.

```bash
nc -zv -w 2 10.10.30.20 5432
```
**timeout**: no baseline rule allows this port.

---

## Part E: Apply segmentation live (router, then kali and web, about 2 min)

On **lab-router**:
```bash
sudo firewall-segmented.sh
```
The new rules are printed: users → web 80/443 only; web → db 5432 only; everything else dropped.

On **kali**:
```bash
nc -zv -w 2 10.10.30.20 22
```
Now **timeout**: Kali can no longer reach the database directly.

```bash
nc -zv -w 2 10.10.20.10 80
```
Still **open**: users can still use the website.

On **lab-web**:
```bash
nc -zv -w 2 10.10.30.20 5432
```
**open**: the web server can still reach its database.

**Say:** "This is exactly what the tool predicted: after segmentation the only route to the database is Kali → web → database, so web is the choke point."

---

## Part F: The tool's prediction (Windows, about 1 min)

From the project folder:

```bash
.\.venv\Scripts\python main.py compare --data data/lab.json --start 10.10.10.5 --after data/firewall_segmented.json --html-dir evidence
```
Then open `evidence\after.html`: the same result as a graph.

```bash
.\.venv\Scripts\python lab\compare_results.py data\lab.json evidence\measurements.csv
```
72 of 72 recorded measurements matched the model's predictions.

---

## After the demo

On **lab-router**, restore the baseline policy:
```bash
sudo firewall-baseline.sh
```
Then shut down each VM: **VirtualBox → right-click → Stop → ACPI Shutdown**.

## If something goes wrong

| Problem | Fix |
|---|---|
| VM shows "soft lockup" or is very slow | Wait a minute, or restart that VM |
| `nc` hangs | It times out after 2 s; that means the connection is **blocked** |
| Login loops back to `login:` | Type the username and password again within 60 s |
| A VM won't start | Close more apps; the lab needs about 5 GB of free RAM |
