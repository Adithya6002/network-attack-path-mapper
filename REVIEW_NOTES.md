# Review Notes: Network Attack Path Mapper

Quick answers to the questions most likely to come up in the review, in the order they were discussed.

---

## 1. What does the project do?

- Takes **hosts, open services, subnets and firewall rules**, and builds a **graph** of who can reach whom.
- Answers: which hosts an intruder on one computer can reach, **along which paths**, through which **choke points**, and **what a firewall change does**.
- The model was checked in a **real 4-VM lab**: **72/72** measured connections matched (95% CI 95.0–100%), so it's **TRL 3**.

---

## 2. How is it different from Nmap? What does "missed" mean?

- **Nmap** only tests connections **from the machine it runs on**, one hop.
- **My tool** models the **whole network**, so it finds routes of **2–3 hops**.
- **"Missed"** = the scan said a critical host was **not reachable**, but it **was** reachable through another host (a **false negative**).
- **Lab example (segmented policy):**
  - Kali → db on 22 and 5432: **timeout**, so a scan says "db is safe";
  - but Kali → web on 80 is **open**, and web → db on 5432 is **open**;
  - so db is reachable in **2 hops**: `Kali → web → db`.
- **Experiments:** under all **3 segmented policies**, a scan from the starting host **missed 100%** of the reachable critical hosts. On a flat network it missed none.
- **Be honest:** the "scan" in the experiments was **simulated** (it counted the directly reachable hosts). This isn't a flaw in Nmap; a single scan just can't see multi-hop paths.

---

## 3. What do graph.html, before.html and after.html show?

| File | Command | Policy |
|---|---|---|
| **graph.html** | `main.py analyze` | baseline: the network as it is now |
| **before.html** | `main.py compare` | the **same** baseline, the "before" side |
| **after.html** | `main.py compare` | the stricter **segmented** policy |

- graph.html and before.html show **the same thing**; only the title and layout differ.
- **Before vs. after** is the main demo: **34 → 12** connections, **50+ → 2** paths to the database, db **1 → 2 hops**.

---

## 4. What does an arrow mean?

- **A → B** = A can **start** a connection to at least one **open service** on B.
- **Reachable ≠ hacked.** It only means the network lets the traffic through.
- **One-way**, because firewall rules are one-way. Kali → web exists; web → Kali doesn't (the lab measured **timeouts**).
- Replies are allowed automatically (the firewall is **stateful**), so the arrow shows **who can start** a connection.
- **Arrows chain into paths.** The number of arrows on a path = the number of **hops**.
- **Hover over an arrow** to see its ports, e.g. `5432/tcp postgresql`.

---

## 5. What does a dashed line mean?

- **Dashed** = the hosts are in **different subnets**, so the traffic **goes through the router's firewall**.
- A **firewall rule allowed it**, so a firewall rule **could block it**.
- **Solid** = **same subnet**: the traffic goes through the switch and **never reaches the firewall**, so **no firewall rule can block it**.

| Line | Through the firewall? | Can a firewall rule block it? |
|---|---|---|
| Dashed | Yes | Yes |
| Solid | No | No; needs subnet splitting or a host firewall |

---

## 6. "So the firewall should block it, but it allows it?"

- A firewall is **not** meant to block everything. It **allows needed traffic** and blocks the rest.
- **Needed:** users → web on 443; web → db on 5432. Block these and the website breaks.
- **Unneeded:** e.g. users → db on SSH (22) in the *before* policy. That's a loose rule and a direct route for an intruder.
- **The key insight:** even when every allowed rule is fine **by itself**, they can **chain** into a path (`Kali → web → db`). Rule-by-rule review can't see that; the graph can.
- **Misconfiguration example (experiments):** one extra rule, users → management on RDP (3389), brought about **38** critical servers within **2 hops**. Only the tool caught it.

---

## 7. Are dashed and thick lines the same?

- **No. They answer two different questions:**
  - **Dashed vs. solid:** does it cross the firewall?
  - **Thick red vs. thin grey:** is it on a route to a **critical** host?

| Line | Example (after.html) |
|---|---|
| Thick red + dashed | web → db (5432) |
| Thick red + solid | db → fileserver (same subnet) |
| Thin grey + dashed | a harmless allowed connection |
| Thin grey + solid | web → mail (same DMZ subnet) |

---

## 8. Explaining graph.html (the baseline picture)

- **Red star** = **kali 10.10.10.5**, the starting host.
- **Orange diamonds** = **db 10.10.30.20** and **fileserver 10.10.30.25**, the critical hosts.
- **Circles** = other hosts, coloured by subnet: workstation (user-lan), web and mail (DMZ), metasploitable (internal).
- **34 lines**, almost all **red** and mostly **dashed**: the loose policy lets almost everything reach everything.
- **Dashed lines straight from Kali to db and fileserver**: critical hosts are **1 hop** away.
- **Solid lines:** kali ↔ workstation, web ↔ mail, db ↔ fileserver ↔ metasploitable (same subnets).
- **If asked "why is everything red?":** under a loose policy almost every connection really is on a route to a critical host, and that's the warning. Red becomes selective after segmentation.

---

## 9. Where did the sample network come from?

- It's a **demonstration network** (`data/network.json`), **designed**, not scanned.
- Based on the project plan's machines (Kali, Ubuntu Server, Metasploitable) arranged as a **typical 3-zone company network**: user-lan, DMZ, internal.
- The baseline firewall is **deliberately loose**, so the before/after demo has a problem to fix.
- **Nobody drew the lines.** The tool **calculates** every one from the subnets, services and firewall rules.
- **Real-network evidence is the lab** (`data/lab.json`), with **72/72** matched.

---

## 10. What is Metasploitable?

- A **deliberately insecure training VM** (from Rapid7), full of old, unpatched services, used to **practise safely** in isolated labs.
- It must **never** be connected to the internet or a real network.
- **In the sample network:** it stands for an **old, forgotten server** in the internal subnet, next to the critical servers.
- **Lesson:** it shares a subnet with db and fileserver, so the firewall can't stop movement from it to them.
- **Not used in the real lab.** Reachability testing didn't need it.
- **The tool doesn't test vulnerabilities**; it only shows that a host is **reachable**.

---

## 11. What is Kali used for?

- **Sample network:** the **red star**, i.e. a **compromised user workstation**. All hops and paths are measured from it.
- **Real lab (10.10.10.5):**
  - played the starting host;
  - **measurement point:** ran `measure.sh` (TCP connection tests, giving open/refused/timeout);
  - ran the tool and its tests inside the lab;
  - confirmed routing through lab-router.
- **Why Kali:** it's in the project plan, has Python and Nmap preinstalled, comes as a ready-made VirtualBox image, and is the standard choice for security labs.
- **No attacking.** It only made connection tests inside an isolated lab.

---

## 12. What does after.html show?

- **New policy:** users → web on 80/443; web → db on 5432; **everything else denied**.
- **12 lines:**
  - **solid** (same subnet): kali → workstation; web ↔ mail; the 6 lines between db, fileserver and metasploitable;
  - **dashed** (allowed business traffic): kali → web, workstation → web, web → db.
- **Red route:** `kali → web → db → fileserver`.

| Host | Hops before | Hops after |
|---|---|---|
| db | 1 | **2** (only through web) |
| fileserver | 1 | **3** (only through db) |
| mail | 1 | 2 |
| metasploitable | 1 | 3 |

- **What it proves:**
  1. the policy worked (34 → 12 connections, 50+ → 2 paths);
  2. **web became a choke point**;
  3. **the file server is still exposed**, because db → fileserver is solid (same subnet). The fix is splitting the subnet.

---

## 13. "So even after segmentation the database can be attacked?"

- It's still **reachable**, but much **harder** to reach:
  1. the intruder must **take over the web server first** (only ports 80/443 are open to Kali);
  2. then they can only use **port 5432**, and still need database credentials or a database flaw.
- **It can't be zero:** the website **needs** web → db on 5432. A firewall can't block traffic the business depends on.
- What remains is **residual risk**, handled with other layers (**defence in depth**):
  - harden and patch the web server, plus a web application firewall;
  - **monitor web** (the choke point covers every route);
  - strong database credentials and least privilege;
  - split the internal subnet, or firewall each server.
- **The tool's value:** a rule review says "no rule from users to the database, so it's safe". The tool shows the real 2-hop route.

---

## 14. What is a choke point?

- A host that **every route** to a target **must pass through**. There's no way around it.
- **Analogy:** the security desk at the only entrance to the server room.
- **after.html:** both routes Kali → db go through **web**, so **web is a choke point for db**. **db is a choke point for fileserver.**
- **Why it's useful:** defend that one host and you protect **all** routes behind it.
- **before.html had no choke points.** Segmentation **created** them.
- **Algorithm:** **dominator tree**. D dominates T if every path from the start to T passes through D.

---

## 15. Research contribution, or just tools put together?

- The tools are standard (Nmap, NetworkX, firewall rules).
- **The contribution:**
  1. a **host- and service-level model** that includes **traffic inside subnets** (which rule-based analysis ignores);
  2. **validation on a real network**: the same policy file drives both the model and the router, and **72/72** matched;
  3. **measured failure rates of common approaches**: scans and rule reviews **missed 100%** of multi-hop exposure; zone review gave **49% false alarms** and missed the misconfiguration;
  4. **choke points** (dominator trees) used for comparing firewall policies.
- **Don't claim** the faster path search is new (it uses standard pruning), or that the tool finds exploits.
- **Future work:** an optimal **hardening recommender** (a minimum cut that finds the smallest firewall change cutting all paths to critical hosts).

---

## Numbers to remember

| What | Number |
|---|---|
| Sample network | 7 hosts, 3 subnets; **34 → 12** lines; **50+ → 2** paths; db **1 → 2** hops |
| Lab | 4 VMs, 3 subnets, **72/72** matched, 95% CI **95.0–100%** |
| Experiments | **360** runs; scans missed **100%**; zone review **49%** false alarms |
| Speed | 1,000 hosts in **< 15 s**; path search **217 s → 1.2 s** |
| Tests | **41** |
| TRL | **3** |
