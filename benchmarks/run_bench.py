#!/usr/bin/env python3
"""Measure graph stages and verify labeled offline fixtures."""
import argparse
import json
import math
import platform
import statistics
from collections import Counter
from pathlib import Path
from time import perf_counter_ns

from kubeblast.graph import analyze, build_graph, find_paths, read_inventory
from kubeblast.models import Inventory, Node
from kubeblast.remediate import minimum_cut_set

ROOT = Path(__file__).resolve().parents[1]
EXPECTED = {
    "vulnerable": {
        ("k8s:user:observer", "k8s:node-proxy:worker-a"),
        ("k8s:workload:demo:Pod:runner", "aws:admin-capability"),
        ("k8s:workload:demo:Pod:runner", "aws:secret:*"),
        ("k8s:workload:demo:Pod:runner", "gcp:grant:projects/demo-project:roles/owner"),
    },
    "hardened": set(),
}


def synthetic(size: int) -> Inventory:
    inventory = Inventory()
    for index in range(size):
        inventory.add(Node(
            id=str(index), label=f"Synthetic identity {index}",
            kind=("workload", "service_account", "iam_role", "iam_role", "iam_role")[index % 5],
            entry=index % 5 == 0, impact=8 if index % 5 in {2, 3, 4} else 0,
        ))
    for index in range(0, size, 5):
        inventory.link(str(index), str(index + 1), "k8s_workload_identity", "synthetic")
        for offset, rule in enumerate(("aws_irsa", "gcp_workload_identity", "azure_entra_federated"), 2):
            inventory.link(str(index + 1), str(index + offset), rule, "synthetic")
        if index + 5 < size:
            inventory.link(str(index + 3), str(index + 6), "gcp_binding", "synthetic")
    return inventory


def times(samples):
    return {
        "p50_ms": round(statistics.median(samples), 3),
        "p95_ms": round(sorted(samples)[math.ceil(0.95 * len(samples)) - 1], 3),
    }


def measure(size, repetitions):
    inventory = synthetic(size)
    find_paths(build_graph(inventory))
    construction, pathfinding = [], []
    for _ in range(repetitions):
        start = perf_counter_ns()
        graph = build_graph(inventory)
        built = perf_counter_ns()
        find_paths(graph)
        finished = perf_counter_ns()
        construction.append((built - start) / 1_000_000)
        pathfinding.append((finished - built) / 1_000_000)
    return {
        "nodes": size, "edges": len(inventory.edges),
        "construction": times(construction), "pathfinding": times(pathfinding),
    }


def high_risk_pairs(report, impact=7):
    return {
        (path["nodes"][0], path["nodes"][-1])
        for path in report["paths"] if path["impact"] >= impact
    }


def verify_fixtures():
    per_fixture = {}
    for name, expected in EXPECTED.items():
        inventory = read_inventory([ROOT / "examples" / "wave6" / name])
        report = analyze(inventory)
        detected = high_risk_pairs(report)
        cut = minimum_cut_set(report)
        remove = Counter(json.dumps(edge, sort_keys=True) for edge in cut["edges"])
        surviving = []
        for edge in inventory.edges:
            key = json.dumps(edge.model_dump(), sort_keys=True)
            if remove[key]:
                remove[key] -= 1
            else:
                surviving.append(edge)
        after = analyze(Inventory(nodes=inventory.nodes, edges=surviving))
        per_fixture[name] = {
            "true_positives": len(expected & detected),
            "false_positives": len(detected - expected),
            "false_negatives": len(expected - detected),
            "cut_edges": len(cut["edges"]),
            "remaining_high_risk_pairs": len(high_risk_pairs(after)),
        }
        if detected != expected or any(remove.values()) or not cut["complete"] or high_risk_pairs(after):
            raise ValueError(
                f"{name}: graph labels or cut-set verification failed "
                f"(missing={expected - detected}, unexpected={detected - expected}, "
                f"remaining={high_risk_pairs(after)})"
            )
        # The AWS, GCP, and Kubernetes paths share no removable edge.
        # The two AWS targets can both be cut at the EKS trust.
        if len(cut["edges"]) != (3 if name == "vulnerable" else 0):
            raise ValueError(f"{name}: cut does not meet the fixture's cardinality bound")
    totals = Counter()
    for metrics in per_fixture.values():
        totals.update(metrics)
    tp = totals["true_positives"]
    return {
        "fixtures": per_fixture,
        "precision": tp / (tp + totals["false_positives"]),
        "recall": tp / (tp + totals["false_negatives"]),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repetitions", default=30, type=int)
    args = parser.parse_args()
    if args.repetitions < 1:
        parser.error("--repetitions must be positive")
    print(json.dumps({
        "python": platform.python_version(), "platform": platform.platform(),
        "repetitions": args.repetitions,
        "graphs": [measure(size, args.repetitions) for size in (500, 2000)],
        **verify_fixtures(),
    }, indent=2))


if __name__ == "__main__":
    main()
