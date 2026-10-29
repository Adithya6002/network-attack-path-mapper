"""Tests for the lab tooling (policy -> iptables, model-vs-lab comparison)
and the experiment code (generator, baselines)."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from analyzer.graph import build_graph, is_allowed
from experiments.baselines import single_vantage, zone_level
from experiments.generate import generate_network, policies

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lab"))

from compare_results import confusion, exact_ci, predict  # noqa: E402
from json_to_iptables import rule_lines, to_script  # noqa: E402


# --- lab/json_to_iptables.py ------------------------------------------------

def test_iptables_script_has_guard_state_and_default():
    policy = json.loads((ROOT / "data" / "network.json").read_text(encoding="utf-8"))["firewall"]
    script = to_script(policy, "network.json").splitlines()
    assert script[0] == "#!/bin/sh"
    assert "iptables -P FORWARD DROP" in script
    # The isolation guard and the stateful rule come before any policy rule.
    guard = script.index("iptables -A FORWARD -i enp0s10 -j DROP")
    state = script.index("iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT")
    first_policy = next(i for i, l in enumerate(script) if "-s 10.10.10.0/24" in l)
    assert guard < state < first_policy


def test_iptables_rule_translation():
    assert rule_lines({"action": "allow", "src": "10.0.0.0/24", "dst": "any", "ports": "any"}) == [
        "iptables -A FORWARD -s 10.0.0.0/24 -j ACCEPT"
    ]
    assert rule_lines({"action": "deny", "src": "any", "dst": "10.0.1.5/32", "ports": [22, 80], "proto": "tcp"}) == [
        "iptables -A FORWARD -d 10.0.1.5/32 -p tcp -m multiport --dports 22,80 -j DROP"
    ]
    # proto "any" with ports needs one line per protocol.
    assert len(rule_lines({"action": "allow", "src": "any", "dst": "any", "ports": [53]})) == 2


def test_committed_router_scripts_match_policy_files():
    """The scripts deployed on lab-router must be exactly what the JSON generates."""
    for src, script in (("network.json", "firewall-baseline.sh"),
                        ("firewall_segmented.json", "firewall-segmented.sh")):
        data = json.loads((ROOT / "data" / src).read_text(encoding="utf-8"))
        expected = to_script(data.get("firewall", data), src)
        assert (ROOT / "lab" / "router" / script).read_text(encoding="ascii") == expected


# --- lab/compare_results.py -------------------------------------------------

def test_predict_firewall_and_service():
    lab = json.loads((ROOT / "data" / "lab.json").read_text(encoding="utf-8"))
    fw = lab["firewall"]
    assert predict(lab, fw, "10.10.20.10", "10.10.30.20", 5432) == (True, True)    # allowed, listening
    assert predict(lab, fw, "10.10.20.10", "10.10.30.20", 8080) == (True, False)   # allowed, no service
    assert predict(lab, fw, "10.10.10.5", "10.10.30.20", 5432) == (False, False)   # dropped


def test_confusion_counts():
    counts, acc = confusion([(True, True), (False, False), (True, False), (False, True)])
    assert (counts["TP"], counts["TN"], counts["FP"], counts["FN"]) == (1, 1, 1, 1)
    assert acc == 0.5


def test_exact_ci_known_values():
    lo, hi = exact_ci(72, 72)
    assert hi == 1.0 and abs(lo - 0.025 ** (1 / 72)) < 1e-6     # closed form when k = n
    lo, hi = exact_ci(5, 10)                                     # textbook: 0.187 - 0.813
    assert abs(lo - 0.1871) < 1e-3 and abs(hi - 0.8129) < 1e-3


def test_predict_connection_matches_all_lab_measurements():
    """The predict command's function reproduces all 72 measured lab results."""
    from analyzer.graph import predict_connection

    lab = json.loads((ROOT / "data" / "lab.json").read_text(encoding="utf-8"))
    policies = {"baseline": lab["firewall"],
                "segmented": json.loads((ROOT / "data" / "firewall_segmented.json").read_text(encoding="utf-8"))}
    rows = (ROOT / "evidence" / "measurements.csv").read_text(encoding="utf-8").splitlines()[1:]
    assert len(rows) == 72
    for row in rows:
        policy, src, dst, port, measured = row.split(",")
        assert predict_connection(lab, policies[policy], src, dst, int(port)) == measured, row


def test_recorded_lab_validation_is_72_of_72():
    out = subprocess.run(
        [sys.executable, str(ROOT / "lab" / "compare_results.py"),
         str(ROOT / "data" / "lab.json"), str(ROOT / "evidence" / "measurements.csv")],
        capture_output=True, text=True, check=True,
    ).stdout
    assert "| **all** | Firewall decision | 72 |" in out
    assert "No mismatches" in out


# --- experiments ------------------------------------------------------------

def test_generator_is_deterministic_and_valid():
    a = generate_network(200, subnets_per_zone=2, seed=3)
    b = generate_network(200, subnets_per_zone=2, seed=3)
    assert a == b
    ips = [h["ip"] for h in a["hosts"]]
    assert len(ips) == len(set(ips))
    assert all(int(ip.rsplit(".", 1)[1]) <= 254 for ip in ips)
    assert any(h["role"] == "database" for h in a["hosts"])
    assert any(h["role"] == "fileserver" for h in a["hosts"])


def test_separated_design_keeps_fileservers_out_of_db_subnet():
    net = generate_network(200, subnets_per_zone=2, seed=0, separate_fileservers=True)
    db_subnet = next(s["cidr"] for s in net["subnets"] if s["zone"] == "data").rsplit(".", 1)[0]
    for h in net["hosts"]:
        if h["role"] == "fileserver":
            assert not h["ip"].startswith(db_subnet + ".")


def test_misconfig_rule_shortens_path_to_data():
    net = generate_network(150, subnets_per_zone=1, seed=1)
    pols = policies(net)
    user = next(h["ip"] for h in net["hosts"] if h["role"] == "user")
    mgmt = next(s["cidr"] for s in net["subnets"] if s["zone"] == "mgmt")
    assert not is_allowed(pols["tiered"], user, mgmt.replace("0/24", "10"), 3389)
    assert is_allowed(pols["tiered+misconfig"], user, mgmt.replace("0/24", "10"), 3389)


@pytest.mark.parametrize("policy", ["flat", "permissive", "tiered", "tiered+misconfig"])
def test_baselines_bound_the_tool(policy):
    """Scan sees a subset of the tool's reachable set; zone review a superset."""
    net = generate_network(120, subnets_per_zone=2, seed=2, separate_fileservers=True)
    fw = policies(net)[policy]
    graph = build_graph(net, fw)
    start = next(h["ip"] for h in net["hosts"] if h["role"] == "user")
    import networkx as nx
    ours = nx.descendants(graph, start)
    assert single_vantage(graph, start) <= ours
    assert ours <= zone_level(net, fw, start)
