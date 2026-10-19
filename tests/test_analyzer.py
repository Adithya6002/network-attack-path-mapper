import json
from pathlib import Path

import pytest

from analyzer.graph import build_graph, is_allowed
from analyzer.paths import analyze, compare
from collector.parser import parse_nmap_xml
from collector.scanner import validate_targets

DATA = Path(__file__).resolve().parent.parent / "data"
KALI, WEB, DB, FILES = "10.10.10.5", "10.10.20.10", "10.10.30.20", "10.10.30.25"


@pytest.fixture
def network():
    return json.loads((DATA / "network.json").read_text(encoding="utf-8"))


@pytest.fixture
def segmented():
    return json.loads((DATA / "firewall_segmented.json").read_text(encoding="utf-8"))


def test_firewall_first_match_and_default():
    fw = {"default": "deny", "rules": [
        {"action": "deny", "src": "10.0.0.5/32", "dst": "any", "ports": "any"},
        {"action": "allow", "src": "10.0.0.0/24", "dst": "10.0.1.0/24", "ports": [80]},
    ]}
    assert is_allowed(fw, "10.0.0.7", "10.0.1.1", 80)
    assert not is_allowed(fw, "10.0.0.5", "10.0.1.1", 80)
    assert not is_allowed(fw, "10.0.0.7", "10.0.1.1", 22)


def test_same_subnet_bypasses_firewall(network):
    graph = build_graph(network, {"default": "deny", "rules": []})
    assert graph.has_edge(KALI, "10.10.10.20")
    assert not graph.has_edge(KALI, WEB)


def test_baseline_reaches_critical_hosts_directly(network):
    result = analyze(build_graph(network), KALI)
    assert result["reachable"][DB] == 1
    assert result["reachable"][FILES] == 1


def test_segmentation_forces_path_through_web(network, segmented):
    result = analyze(build_graph(network, segmented), KALI)
    assert result["reachable"][DB] == 2
    assert result["target_paths"][DB][0] == [KALI, WEB, DB]
    assert DB in result["choke_points"][WEB]
    # The fileserver shares the internal subnet with the db, so the firewall
    # can't stop db -> fileserver: it's still reachable, just one hop further.
    assert result["reachable"][FILES] == 3
    assert FILES in result["choke_points"][DB]


def test_compare_reports_lost_reachability(network, segmented):
    before = analyze(build_graph(network), KALI)
    after = analyze(build_graph(network, segmented), KALI)
    diff = compare(before, after)
    assert diff["edges"][1] < diff["edges"][0]
    assert diff["hop_changes"][DB] == (1, 2)
    assert diff["hop_changes"][FILES] == (1, 3)

    # Removing the web -> db rule cuts off the whole internal subnet.
    no_db = dict(segmented, rules=[r for r in segmented["rules"] if r.get("ports") != [5432]])
    cut = compare(before, analyze(build_graph(network, no_db), KALI))
    assert {DB, FILES} <= set(cut["no_longer_reachable"])


@pytest.mark.parametrize("seed", range(20))
def test_pruned_path_search_matches_networkx(seed):
    import networkx as nx
    from analyzer.paths import paths_to

    g = nx.gnp_random_graph(14, 0.25, seed=seed, directed=True)
    expected = {tuple(p) for p in nx.all_simple_paths(g, 0, 13, cutoff=4)}
    got = paths_to(g, 0, 13, max_hops=4, limit=10_000)
    assert {tuple(p) for p in got} == expected
    assert [len(p) for p in got] == sorted(len(p) for p in got)  # shortest first


def test_scanner_rejects_public_ranges():
    validate_targets(["192.168.56.0/24", "10.0.0.0/8"])
    with pytest.raises(ValueError):
        validate_targets(["8.8.8.0/24"])


def test_parse_nmap_xml():
    xml = """<nmaprun>
      <host><status state="up"/><address addr="192.168.56.101" addrtype="ipv4"/>
        <hostnames><hostname name="msf"/></hostnames>
        <ports>
          <port protocol="tcp" portid="21"><state state="open"/>
            <service name="ftp" product="vsftpd" version="2.3.4"/></port>
          <port protocol="tcp" portid="25"><state state="closed"/></port>
        </ports></host>
      <host><status state="down"/><address addr="192.168.56.102" addrtype="ipv4"/></host>
    </nmaprun>"""
    hosts = parse_nmap_xml(xml)
    assert len(hosts) == 1
    assert hosts[0]["hostname"] == "msf"
    assert hosts[0]["ports"] == [
        {"port": 21, "proto": "tcp", "service": "ftp", "product": "vsftpd 2.3.4"}
    ]
