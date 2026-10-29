"""Evidence tooling must reject incomplete data and report actual network sizes."""

import csv
import json

import pytest

from analyzer.graph import build_graph
from experiments.benchmark_large import run_case, summarize, worker
from experiments.generate import generate_network
from lab.namespace_lab import PROBES, scenarios
from lab.validate_namespace import evaluate


@pytest.mark.parametrize("size", [10, 35, 250, 1000, 2000])
def test_generator_preserves_requested_size(size):
    network = generate_network(size, subnets_per_zone=4)
    assert len(network["hosts"]) == size
    assert len({h["ip"] for h in network["hosts"]}) == size


def test_generator_refuses_silent_truncation_or_overlapping_zones():
    with pytest.raises(ValueError, match="capacity"):
        generate_network(2000, subnets_per_zone=1)
    with pytest.raises(ValueError, match="overlapping"):
        generate_network(2000, subnets_per_zone=17)


def test_benchmark_worker_records_resources_and_deterministic_inputs():
    a, b = worker(20, "tiered", 0, 4), worker(20, "tiered", 0, 4)
    assert a["actual_hosts"] == 20
    assert a["input_sha256"] == b["input_sha256"]
    assert a["peak_memory_mb"] > 0
    assert a["total_s"] >= 0


def test_isolated_benchmark_roundtrip():
    row = run_case(20, "tiered", 0, 1, 30, 1024)
    assert row["status"] == "ok", row
    assert row["actual_hosts"] == 20
    assert row["peak_memory_mb"] > 0
    summary = summarize([row])
    assert "1/1" in summary
    assert "not real-host connectivity validation" in summary


def test_benchmark_enforces_timeout_and_stops_worker_tree():
    row = run_case(2000, "flat", 0, 1, 0.01, 2048)
    assert row["status"] == "timeout", row
    assert row["wall_s"] < 15


def test_benchmark_enforces_memory_budget():
    row = run_case(2000, "flat", 0, 1, 30, 16)
    assert row["status"] == "memory_limit", row
    assert row["wall_s"] < 15


def write_fixture(folder, omit=False, duplicate=False, infrastructure_error=False):
    networks = scenarios()
    manifest = {"completed": True, "policies": list(networks), "probes": PROBES}
    (folder / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    rows = []
    for label, network in networks.items():
        (folder / f"{label}.json").write_text(json.dumps(network), encoding="utf-8")
        for src in network["hosts"]:
            for dst in network["hosts"]:
                if src is dst:
                    continue
                for port, proto in PROBES:
                    # Deliberately synthetic parser fixture, never presented as lab evidence.
                    rows.append({"policy": label, "source": src["ip"], "destination": dst["ip"],
                                 "port": port, "proto": proto, "result": "timeout"})
    if omit:
        rows.pop()
    if duplicate:
        rows.append(rows[0])
    if infrastructure_error:
        rows[0]["result"] = "error"
    with (folder / "measurements.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


@pytest.mark.parametrize("mode", ["omit", "duplicate", "infrastructure_error"])
def test_validator_refuses_incomplete_or_invalid_evidence(tmp_path, mode):
    write_fixture(tmp_path, **{mode: True})
    with pytest.raises(ValueError):
        evaluate(tmp_path)


def test_validator_reports_mismatches_instead_of_claiming_success(tmp_path):
    write_fixture(tmp_path)
    report, text = evaluate(tmp_path)
    assert report["measurement_count"] == 1980
    assert report["mismatches"]
    assert "Mismatched observations" in text


def test_expanded_lab_has_realistic_policy_changes():
    networks = scenarios()
    assert all(len(n["hosts"]) == 12 for n in networks.values())
    segmented, hardened = build_graph(networks["segmented"]), build_graph(networks["hardened"])
    assert segmented.has_edge("10.44.40.11", "10.44.40.12")
    assert not hardened.has_edge("10.44.40.11", "10.44.40.12")
    assert hardened.has_edge("10.44.30.11", "10.44.40.11")
