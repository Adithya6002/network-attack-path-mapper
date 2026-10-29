"""Regression coverage for policy validation, scan boundaries, and richer reports."""

import copy
import json
import subprocess
from pathlib import Path
from unittest.mock import patch

import networkx as nx
import pyvis
import pytest

from analyzer.graph import build_graph, explain_connection, is_allowed, predict_connection
from analyzer.paths import analyze, compare, paths_to
from analyzer.remediation import recommend
from analyzer.validation import validate_firewall
from collector.scanner import run_nmap, validate_nmap_args, validate_targets
from lab.json_to_iptables import rule_lines, to_script
from lab.compare_results import predict
from main import main, print_report
from visualization.visualize import render, render_comparison

ROOT = Path(__file__).resolve().parent.parent
A, B, C = "10.0.0.10", "10.0.1.10", "10.0.1.20"


@pytest.fixture
def network():
    return {
        "subnets": [{"name": "users", "cidr": "10.0.0.0/24"}, {"name": "servers", "cidr": "10.0.1.0/24"}],
        "hosts": [
            {"ip": A, "ports": []},
            {"ip": B, "critical": True, "ports": [{"port": 22, "service": "ssh"}, {"port": 443, "service": "https"}]},
            {"ip": C, "ports": [{"port": 53, "proto": "udp", "service": "domain"}]},
        ],
        "firewall": {"default": "allow", "rules": []},
    }


@pytest.mark.parametrize("field,value", [
    ("action", "alow"), ("proto", "icmp"), ("src", "::/0"),
    ("dst", "10.0.0.1; echo injected"), ("ports", []), ("ports", [True]),
    ("ports", [0]), ("ports", [65536]), ("ports", [22, 22]), ("ports", "22"),
])
def test_reject_invalid_rule(field, value):
    rule = {"action": "allow", "ports": "any", field: value}
    with pytest.raises(ValueError):
        validate_firewall({"default": "deny", "rules": [rule]})


@pytest.mark.parametrize("policy", [{}, {"default": "alow"}, {"default": "deny", "rule": []},
                                     {"default": "deny", "rules": {}}, {"default": "deny", "rules": [None]}])
def test_reject_invalid_policy(policy):
    with pytest.raises(ValueError):
        validate_firewall(policy)


@pytest.mark.parametrize("mutation", ["duplicate_ip", "duplicate_subnet", "overlap", "ipv6", "critical", "port", "proto", "outside", "missing_firewall"])
def test_reject_ambiguous_network(network, mutation):
    if mutation == "duplicate_ip":
        network["hosts"].append(copy.deepcopy(network["hosts"][1]))
    elif mutation == "duplicate_subnet":
        network["subnets"][1]["name"] = "users"
    elif mutation == "overlap":
        network["subnets"][1]["cidr"] = "10.0.0.0/16"
    elif mutation == "ipv6":
        network["hosts"][0]["ip"] = "::1"
    elif mutation == "critical":
        network["hosts"][1]["critical"] = "false"
    elif mutation == "port":
        network["hosts"][1]["ports"][0]["port"] = -1
    elif mutation == "proto":
        network["hosts"][1]["ports"][0]["proto"] = "any"
    elif mutation == "outside":
        network["hosts"][0]["ip"] = "10.4.0.1"
    else:
        del network["firewall"]
    with pytest.raises(ValueError):
        build_graph(network)


def test_ipv4_rule_cannot_match_ipv6():
    with pytest.raises(ValueError, match="IPv4"):
        is_allowed({"default": "deny", "rules": [{"action": "allow", "src": "0.0.0.0/0"}]}, "::1", "::2", 80)


def test_host_firewall_applies_inside_and_across_subnets(network):
    network["hosts"][1]["firewall"] = {"default": "deny", "rules": [
        {"action": "allow", "src": f"{A}/32", "ports": [443]},
    ]}
    graph = build_graph(network)
    assert [p["port"] for p in graph.edges[A, B]["services"]] == [443]
    assert not graph.has_edge(C, B)
    assert graph.edges[A, B]["reasons"] == ["network default (allow); host inbound rule 1 (allow)"]
    assert "host inbound default (deny)" in explain_connection(graph, C, B, 22)
    # Host allows cannot override a routed network deny.
    denied = build_graph(network, {"default": "deny", "rules": []})
    assert not denied.has_edge(A, B)
    assert predict(network, network["firewall"], C, B, 22) == (False, False)
    assert predict(network, network["firewall"], A, C, 53) == (True, False)  # UDP listener is not TCP
    assert predict_connection(network, network["firewall"], A, B, 443) == "open"
    assert predict_connection(network, network["firewall"], C, B, 22) == "timeout"
    with pytest.raises(ValueError, match="must exist"):
        predict_connection(network, network["firewall"], "10.0.0.99", B, 22)


def test_first_match_explanation_and_protocol_distinction(network):
    network["hosts"][1]["ports"].append({"port": 443, "proto": "udp"})
    network["firewall"] = {"default": "deny", "rules": [
        {"action": "deny", "ports": [22]}, {"action": "allow", "ports": [443], "proto": "tcp"},
    ]}
    graph = build_graph(network)
    assert graph.edges[A, B]["reasons"] == ["network rule 2 (allow)"]
    assert explain_connection(graph, A, B, 22) == "network rule 1 (deny)"
    assert explain_connection(graph, A, B, 443, "udp") == "network default (deny)"


def test_graph_explanations_are_snapshots_of_the_original_input(network):
    graph = build_graph(network)
    network["firewall"]["default"] = "deny"
    network["hosts"][1]["ports"].clear()
    assert explain_connection(graph, A, B, 22) == "network default (allow)"
    assert graph.nodes[B]["ports"]


def test_comparison_detects_service_removal_without_edge_or_hop_change(network):
    before_graph = build_graph(network)
    after_graph = build_graph(network, {"default": "allow", "rules": [{"action": "deny", "ports": [22]}]})
    diff = compare(analyze(before_graph, A), analyze(after_graph, A), before_graph, after_graph)
    assert diff["edges"][0] == diff["edges"][1]
    assert not diff["hop_changes"]
    change = next(c for c in diff["service_changes"] if c["source"] == A and c["destination"] == B)
    assert change["removed"][0]["port"] == 22
    assert change["removed"][0]["after_reason"] == "network rule 1 (deny)"
    assert not change["added"]
    reverse = compare(analyze(after_graph, A), analyze(before_graph, A), after_graph, before_graph)
    assert any(c["added"] for c in reverse["service_changes"])


@pytest.mark.parametrize("count,truncated", [(49, False), (50, False), (51, True)])
def test_path_cap_reports_actual_truncation(count, truncated):
    graph = nx.DiGraph()
    for i in range(count):
        graph.add_edges_from([("start", f"via-{i}"), (f"via-{i}", "target")])
    graph.nodes["target"]["critical"] = True
    result = analyze(graph, "start", 2)
    assert result["paths_truncated"]["target"] is truncated
    assert len(result["target_paths"]["target"]) == min(count, 50)


def test_long_path_search_does_not_depend_on_python_recursion_limit():
    graph = nx.path_graph(1100, create_using=nx.DiGraph)
    assert paths_to(graph, 0, 1099, max_hops=1099) == [list(range(1100))]


def test_report_distinguishes_unreachable_and_beyond_hop_limit(network, capsys):
    graph = build_graph(network)
    graph.remove_edge(A, B)
    graph.nodes[C]["critical"] = True
    graph.remove_edge(A, C)
    result = analyze(graph, A, 1)
    print_report(graph, result)
    assert "unreachable" in capsys.readouterr().out
    graph.add_edge(A, C, services=[{"port": 53, "proto": "udp"}])
    result = analyze(graph, A, 1)
    print_report(graph, result)
    assert "beyond the 1-hop display limit" in capsys.readouterr().out


@pytest.mark.parametrize("args", [["8.8.8.8"], ["-iL", "targets.txt"], ["--script", "unsafe"],
                                  ["-oX", "other.xml"], ["--", "8.8.8.8"], ["-p", "80,8.8.8.8"],
                                  ["--top-ports", "0"], ["-p", "100-20"], ["-p"], ["-T9"]])
def test_scanner_rejects_extra_targets_and_unsupported_options(args):
    with patch("collector.scanner.subprocess.run") as process:
        with pytest.raises(ValueError):
            run_nmap(["192.168.56.0/24"], args)
        process.assert_not_called()


@pytest.mark.parametrize("target", ["0.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "::1", "8.8.8.8", "192.168.0.0/15"])
def test_scanner_rejects_non_lab_ranges(target):
    with pytest.raises(ValueError):
        validate_targets([target])


def test_scan_uses_only_validated_options_and_target():
    options = ["-sV", "-p22,80,443", "-T4", "--top-ports", "1000"]
    assert validate_nmap_args(options) == ["-sV", "-p", "22,80,443", "-T4", "--top-ports", "1000"]
    with patch("collector.scanner.shutil.which", return_value="nmap"), patch("collector.scanner.subprocess.run") as process:
        process.return_value.stdout = "<nmaprun/>"
        assert run_nmap(["192.168.56.1/24"], options, timeout=10) == "<nmaprun/>"
        assert process.call_args.args[0][-3:] == ["-oX", "-", "192.168.56.0/24"]
        assert process.call_args.kwargs["timeout"] == 10


@pytest.mark.parametrize("error,message", [(subprocess.TimeoutExpired("nmap", 1), "timed out"),
                                          (subprocess.CalledProcessError(2, "nmap", stderr="bad option"), "bad option")])
def test_scan_failures_have_readable_errors(error, message):
    with patch("collector.scanner.shutil.which", return_value="nmap"), patch("collector.scanner.subprocess.run", side_effect=error):
        with pytest.raises(ValueError, match=message):
            run_nmap(["10.0.0.0/24"])


def test_shell_generator_validates_values_and_splits_multiport_rules():
    with pytest.raises(ValueError):
        to_script({"default": "deny", "rules": [{"action": "allow", "src": "any; echo bad"}]}, "policy.json")
    lines = rule_lines({"action": "deny", "ports": list(range(1, 18)), "proto": "tcp"})
    assert len(lines) == 2
    assert "--dports 16,17 -j DROP" in lines[1]


def test_recommendations_preserve_required_flows_and_are_realizable(network):
    graph = build_graph(network)
    required = [{"source": A, "destination": C, "port": 53, "proto": "udp"}]
    report = recommend(graph, A, required)
    assert report["recommendations"]
    assert not any((s["source"], s["destination"]) == (A, C) for s in report["recommendations"])
    for suggestion in report["recommendations"]:
        changed = copy.deepcopy(network)
        if suggestion["placement"] == "network firewall":
            changed["firewall"]["rules"].insert(0, suggestion["rule"])
        else:
            host = next(h for h in changed["hosts"] if h["ip"] == suggestion["destination"])
            host["firewall"] = {"default": "allow", "rules": [suggestion["rule"]]}
        after = build_graph(changed)
        assert after.has_edge(A, C)
        result = analyze(after, A)
        assert all(n not in result["reachable"] for n in suggestion["critical_hosts_protected"])
    # Simulations do not mutate the original graph or data.
    assert graph.number_of_edges() == build_graph(network).number_of_edges()
    with pytest.raises(ValueError, match="not currently allowed"):
        recommend(graph, A, [{"source": A, "destination": B, "port": 9999}])


def test_recommendation_budget_is_explicit(network):
    report = recommend(build_graph(network), A, max_candidates=1)
    assert report["candidates_truncated"]
    assert report["evaluated_candidates"] == 1


def test_recommender_handles_same_segment_controls(network):
    network["firewall"] = {"default": "deny", "rules": [{"action": "allow", "src": f"{A}/32", "dst": f"{C}/32", "ports": [53], "proto": "udp"}]}
    required = [{"source": A, "destination": C, "port": 53, "proto": "udp"}]
    suggestions = recommend(build_graph(network), A, required)["recommendations"]
    host_cut = next(s for s in suggestions if s["destination"] == B)
    assert host_cut["placement"] == "host inbound firewall"
    assert host_cut["critical_hosts_protected"] == [B]
    network["hosts"][1]["firewall"] = {"default": "allow", "rules": [host_cut["rule"]]}
    assert B not in analyze(build_graph(network), A)["reachable"]


def test_reports_are_offline_escape_input_and_limit_display(network, tmp_path):
    network["subnets"][0]["name"] = '<script>alert("subnet")</script>'
    network["hosts"][1]["hostname"] = '</script><img src=x onerror=alert("host")>'
    graph = build_graph(network)
    result = analyze(graph, A)
    html = render(graph, result, tmp_path / "graph.html", title="<script>alert('title')</script>", max_edges=1).read_text(encoding="utf-8")
    assert '<script>alert("subnet")</script>' not in html
    assert '</script><img src=x' not in html
    assert "&lt;script&gt;alert" in html
    assert "Display limited to 1 of" in html
    assert '<script src="http' not in html and '<link href="http' not in html
    # Embedded vendor JS must remain byte-for-byte intact: splitting on Unicode
    # line separators can turn valid JS string literals into syntax errors.
    vendor = Path(pyvis.__file__).parent / "templates/lib/vis-9.1.2/vis-network.min.js"
    assert vendor.read_text(encoding="utf-8") in html
    diff = compare(result, result, graph, graph)
    dashboard = render_comparison(diff, tmp_path / "comparison.html").read_text(encoding="utf-8")
    assert "No direct service changes" in dashboard


def test_cli_writes_nested_json_and_handles_invalid_inputs(network, tmp_path, capsys):
    data = tmp_path / "network.json"
    data.write_text(json.dumps(network), encoding="utf-8")
    output = tmp_path / "nested" / "analysis.json"
    assert main(["analyze", "--data", str(data), "--start", A, "--no-html", "--json", str(output), "--explain"]) == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["connections"][0]["services"][0]["reason"]
    assert main(["analyze", "--data", str(data), "--start", A, "--max-hops", "0", "--no-html"]) == 1
    assert "positive integer" in capsys.readouterr().err
    changed = copy.deepcopy(network)
    changed["hosts"][1]["firewall"] = {"default": "deny", "rules": []}
    after = tmp_path / "after.json"
    after.write_text(json.dumps(changed), encoding="utf-8")
    assert main(["compare", "--data", str(data), "--start", A, "--after", str(after), "--no-html", "--json", str(output)]) == 0
    comparison = json.loads(output.read_text(encoding="utf-8"))["comparison"]
    assert B in comparison["no_longer_reachable"]
    assert any("host inbound default (deny)" in s["after_reason"] for c in comparison["service_changes"] for s in c["removed"])
    assert main(["predict", "--data", str(after), "--sources", A, "--ports", "22"]) == 0
    assert "PREDICT timeout" in capsys.readouterr().out
    data.write_text('{"hosts": [}', encoding="utf-8")
    assert main(["analyze", "--data", str(data), "--start", A, "--no-html"]) == 1
