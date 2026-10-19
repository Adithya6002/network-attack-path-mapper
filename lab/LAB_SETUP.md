# Step 1 — Build the Isolated Lab

Goal: a real VirtualBox network whose firewall enforces **the same policy the analyzer models**, so you can check the tool's predictions against real scans. That check is the evidence you need for TRL 4.

## 0. The lab you are building

```text
                      lab-router (Ubuntu, iptables)
              10.10.10.1      10.10.20.1      10.10.30.1
                  |               |               |
   [lab-user-lan] |      [lab-dmz]|  [lab-internal]|
                  |               |               |
          kali 10.10.10.5   web 10.10.20.10   db 10.10.30.20
                                              metasploitable 10.10.30.15
```

| VM | Network | IP | Purpose | RAM |
|---|---|---|---|---|
| lab-router | all three + temporary NAT | .1 on each | Routes between subnets, enforces the firewall | 1 GB |
| kali | lab-user-lan | 10.10.10.5 | Starting host; runs Nmap and this tool | 2 GB |
| lab-web | lab-dmz | 10.10.20.10 | nginx + SSH | 1 GB |
| lab-db | lab-internal | 10.10.30.20 | PostgreSQL + SSH (**critical**) | 1 GB |
| lab-metasploitable | lab-internal | 10.10.30.15 | Deliberately vulnerable host | 512 MB |

That is about 5.5 GB of RAM in total, which fits in your 15.6 GB. **Shut down your other VMs (WIN11, LINUX, Ubuntu-VM) while the lab is running.**

The lab uses VirtualBox **Internal Networks**, which are not connected to your PC or the internet. "NAT" adapters are used only briefly to install packages, and are disconnected in step 8.

## 1. Downloads (you do this)

| File | Where | Notes |
|---|---|---|
| Ubuntu Server 24.04 LTS ISO | ubuntu.com/download/server | Used for router, web and db |
| Kali Linux **VirtualBox** prebuilt image | kali.org/get-kali → Virtual Machines | `.7z` file; extract it with 7-Zip |
| Metasploitable 2 | sourceforge.net/projects/metasploitable | `.zip` containing a `.vmdk` disk |

Check each download's SHA256 against the value on its official site. In PowerShell: `Get-FileHash <file>`. Write the hashes in your lab notebook.

## 2. Create the VM shells (script)

From the project folder in PowerShell:

```bash
.\lab\create_lab_vms.ps1
```

This creates `lab-router`, `lab-web` and `lab-db` in a VirtualBox group named **cn-lab**, with the correct network adapters. It skips any VM that already exists and never changes your other VMs. If PowerShell blocks the script, run it once with `powershell -ExecutionPolicy Bypass -File .\lab\create_lab_vms.ps1`.

## 3. Install Ubuntu Server on lab-router, lab-web and lab-db

For each of the three:

1. VirtualBox → select the VM → **Settings → Storage** → click the empty DVD → choose the Ubuntu ISO.
2. Start it and install with the defaults, plus:
   - Network screen: the NAT adapter gets an address automatically. Leave the other adapter(s) unconfigured.
   - Tick **Install OpenSSH server**.
   - Use the hostname `lab-router`, `lab-web` or `lab-db` to match the VM.
3. After the reboot, remove the ISO (Settings → Storage).

## 4. Configure lab-router

**Getting project files into a VM.** While a VM has its NAT adapter, it can reach your PC at `10.0.N.2`, where N is one more than the NAT adapter's slot number: **10.0.5.2** from lab-router (adapter 4), **10.0.3.2** from lab-web, lab-db and Kali (adapter 2). On Windows, in the project folder, run:

```bash
py -m http.server 8000 --bind 127.0.0.1
```

Only your own PC can reach this; it isn't exposed to your Wi-Fi. Stop it with Ctrl+C when you're done.

On **lab-router**:

```bash
wget http://10.0.5.2:8000/lab/router/01-lab-router.yaml http://10.0.5.2:8000/lab/router/firewall-baseline.sh http://10.0.5.2:8000/lab/router/firewall-segmented.sh
```

```bash
sudo cp 01-lab-router.yaml /etc/netplan/ && sudo chmod 600 /etc/netplan/01-lab-router.yaml && sudo netplan apply
```

```bash
echo 'net.ipv4.ip_forward=1' | sudo tee /etc/sysctl.d/99-lab.conf && sudo sysctl --system
```

```bash
sudo apt update && sudo apt install -y iptables-persistent
```

```bash
chmod +x firewall-*.sh && sudo ./firewall-baseline.sh && sudo netfilter-persistent save
```

Check with `ip -br addr`. `enp0s3`, `enp0s8` and `enp0s9` should show 10.10.10.1, 10.10.20.1 and 10.10.30.1.

The firewall scripts are **generated from the analyzer's own policy files**. If you change a policy JSON, regenerate the matching script:

```bash
.\.venv\Scripts\python lab\json_to_iptables.py data\network.json lab\router\firewall-baseline.sh
```

Every generated script also blocks routing through the NAT adapter, so lab traffic can never leave through it.

## 5. Configure lab-web and lab-db

Each server needs a static IP on its lab subnet. Create `/etc/netplan/60-lab.yaml` with `sudo nano`.

lab-web:

```yaml
network:
  version: 2
  ethernets:
    enp0s3:
      addresses: [10.10.20.10/24]
      routes: [{to: 10.10.0.0/16, via: 10.10.20.1}]
```

lab-db: the same, with `10.10.30.20/24` and `via: 10.10.30.1`.

Then apply it:

```bash
sudo chmod 600 /etc/netplan/60-lab.yaml && sudo netplan apply
```

The route covers only `10.10.0.0/16`. While the NAT adapter is still connected, internet traffic keeps using NAT and lab traffic goes through the router.

**lab-web:**

```bash
sudo apt update && sudo apt install -y nginx
```

**lab-db:**

```bash
sudo apt update && sudo apt install -y postgresql
```

```bash
echo "listen_addresses = '*'" | sudo tee /etc/postgresql/16/main/conf.d/lab.conf && sudo systemctl restart postgresql
```

If that folder doesn't exist, check your PostgreSQL version with `ls /etc/postgresql`.

## 6. Import Kali

1. Double-click the `.vbox` file from the extracted Kali folder (or VirtualBox → Machine → Add). The image's login is printed on the Kali download page.
2. Settings → Network:
   - **Adapter 1** → Internal Network → `lab-user-lan`;
   - **Adapter 2** → NAT (temporary).
3. In Kali, set a static IP (adjust the connection name if `nmcli con show` lists a different one):

```bash
sudo nmcli con add type ethernet ifname eth0 con-name lab ipv4.method manual ipv4.addresses 10.10.10.5/24 ipv4.routes "10.10.0.0/16 10.10.10.1" && sudo nmcli con up lab
```

4. Copy the project to Kali and install its dependencies. On Windows, make a zip in the project folder:

```bash
Compress-Archive -Path main.py,requirements.txt,pytest.ini,analyzer,collector,visualization,data,lab,tests -DestinationPath lab-transfer.zip -Force
```

Then on Kali, while `http.server` is running on Windows:

```bash
wget http://10.0.3.2:8000/lab-transfer.zip && unzip lab-transfer.zip -d mapper && cd mapper
```

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt && .venv/bin/python -m pytest -q
```

## 7. Metasploitable 2 (never give it internet)

1. VirtualBox → **New**:
   - name `lab-metasploitable`;
   - type Linux, version **Other Linux (32-bit)**;
   - 512 MB RAM;
   - **use the existing `.vmdk`** from the zip as its disk.
2. Settings → Network → **Adapter 1 → Internal Network → `lab-internal`**. No other adapters. **Never** NAT, Bridged or Host-only.
3. Boot it and log in (the default login is in the Metasploitable documentation). Then edit `/etc/network/interfaces` with `sudo nano` so `eth0` reads:

```text
auto eth0
iface eth0 inet static
    address 10.10.30.15
    netmask 255.255.255.0
    gateway 10.10.30.1
```

Then run `sudo /etc/init.d/networking restart`.

## 8. Cut the lab off from the internet

Power off **lab-router**, **lab-web**, **lab-db** and **kali**. Then, in PowerShell:

```bash
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" modifyvm lab-router --nic4 null
```

```bash
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" modifyvm lab-web --nic2 null
```

```bash
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" modifyvm lab-db --nic2 null
```

```bash
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" modifyvm kali --nic2 null
```

(Use Kali's real VM name if it isn't `kali`.) If you later need to install something, temporarily set that one adapter back to `nat` while Metasploitable is **off**.

## 9. Check that the lab works and collect evidence

Start all five VMs. On **Kali**:

1. Check basic reachability:
   - `ping -c2 10.10.10.1` and `ping -c2 10.10.20.10`;
   - `ping -c2 8.8.8.8` must **fail** (this proves isolation).
2. Scan with the tool. It saves Nmap's XML so you keep the raw evidence:

```bash
mkdir -p evidence && sudo nmap -sV -oX evidence/baseline-kali.xml 10.10.10.0/24 10.10.20.0/24 10.10.30.0/24
```

```bash
.venv/bin/python main.py scan --targets 10.10.10.0/24 10.10.20.0/24 10.10.30.0/24 --xml evidence/baseline-kali.xml --out data/lab.json
```

3. Edit `data/lab.json`:
   - rename the subnets to `user-lan`, `dmz` and `internal`;
   - add `"critical": true` to 10.10.30.20;
   - replace its `firewall` block with the one from `data/network.json`;
   - **remove the router's own entries** (10.10.x.1), because the model treats the firewall as a rule set, not a host.
4. Run the analysis:

```bash
.venv/bin/python main.py analyze --data data/lab.json --start 10.10.10.5 --html evidence/baseline.html
```

5. **Compare the model with reality.** This is your first piece of validation data. The model says which services each host can reach. Check a sample of those by hand from the *source* VM, for example on lab-web: `nc -zv 10.10.30.20 5432`. Record each check in your notebook:

| From | To | Port | Model says | Lab result | Match? |
|---|---|---|---|---|---|
| kali | 10.10.30.20 | 22 | reachable | | |
| kali | 10.10.30.20 | 5432 | blocked | | |
| lab-web | 10.10.30.20 | 5432 | reachable | | |

Note that Nmap from Kali only sees what Kali can reach directly. Checks between other hosts, like web → db, are what prove the multi-hop part of the model.

6. Repeat with the stricter policy. On lab-router, run `sudo ./firewall-segmented.sh`. Rescan from Kali into `evidence/segmented-kali.xml`, run `main.py compare`, and fill in the table again.

## Done when

- [ ] All five VMs boot, and Kali can't reach the internet.
- [ ] Baseline and segmented scans are saved in `evidence/`.
- [ ] The model-vs-lab table has at least 20 rows for each policy.
- [ ] Screenshots of the VirtualBox network settings and `iptables -L FORWARD` are saved.

If any row says "no match", that isn't a failure. Write down why it happened (a service bound only to localhost, a host firewall, UDP, and so on). Mismatches like these belong in the paper's "limitations" section.
