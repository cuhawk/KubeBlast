import json
from pathlib import Path

import hcl2
import networkx as nx
import yaml

from .models import Inventory
from .parsers.azure_entra import parse_entra
from .parsers.aws_iam import AWSParser
from .parsers.gcp_iam import parse_gcp
from .parsers.k8s_rbac import KubernetesParser


def read_inventory(paths: list[Path]) -> Inventory:
    files = set()
    for path in paths:
        if not path.exists():
            raise ValueError(f"{path} does not exist")
        files.update(
            item for item in (path.rglob("*") if path.is_dir() else [path])
            if item.is_file() and item.suffix.lower() in {".json", ".yaml", ".yml", ".tf"}
        )
    if not files:
        raise ValueError("No supported input files found")

    inventory = Inventory()
    aws = AWSParser(inventory)
    kubernetes = KubernetesParser(inventory)
    gcp = []
    entra = []
    for path in sorted(files):
        evidence = str(path)
        try:
            contents = path.read_text(encoding="utf-8")
            suffix = path.suffix.lower()
            if suffix == ".tf":
                aws.ingest_hcl(hcl2.loads(contents), evidence)
                continue
            documents = [json.loads(contents)] if suffix == ".json" else yaml.safe_load_all(contents)
            for payload in documents:
                if payload is None:
                    continue
                if not isinstance(payload, dict):
                    raise ValueError("expected a mapping")
                if (
                    "federatedIdentityCredentials" in payload
                    or ("issuer" in payload.get("properties", payload)
                        and "subject" in payload.get("properties", payload))
                    or ("value" in payload and ("appId" in payload or "clientId" in payload))
                ):
                    entra.append((payload, evidence))
                elif "kind" in payload:
                    kubernetes.ingest(payload, evidence)
                elif any(key in payload for key in ("bindings", "iamPolicy", "policy")):
                    gcp.append((payload, evidence))
                elif "AssumeRolePolicyDocument" in payload and "Arn" in payload:
                    aws.ingest({"RoleDetailList": [payload]}, evidence)
                elif "TrustPolicy" in payload and "RoleArn" in payload:
                    aws.ingest({"RoleDetailList": [{
                        "Arn": payload["RoleArn"], "AssumeRolePolicyDocument": payload["TrustPolicy"]
                    }]}, evidence)
                else:
                    aws.ingest(payload, evidence)
        except Exception as exc:
            raise ValueError(f"{path}: {exc}") from exc

    kubernetes.finish()
    aws.finish(kubernetes.aws_accounts)
    for payload, evidence in gcp:
        parse_gcp(payload, inventory, evidence, kubernetes.gcp_accounts)
    # Resolve individual subjects before expanding namespace-wide grants.
    for payload, evidence in entra:
        parse_entra(payload, inventory, evidence, kubernetes.azure_accounts)
    kubernetes.finish_identity_mounts()
    return inventory


def build_graph(inventory: Inventory) -> nx.MultiDiGraph:
    graph = nx.MultiDiGraph()
    for node in inventory.nodes.values():
        graph.add_node(node.id, **node.model_dump())
    for edge in inventory.edges:
        graph.add_edge(edge.source, edge.target, **edge.model_dump())
    return graph


def find_paths(graph: nx.MultiDiGraph, max_hops: int = 8) -> tuple[list[dict], dict]:
    if max_hops < 1:
        raise ValueError("max_hops must be positive")
    routes = nx.DiGraph()
    routes.add_nodes_from(sorted(graph.nodes))
    for edge in sorted((data for _, _, data in graph.edges(data=True)), key=lambda edge: (
        edge["conditional"], edge["rule"], edge["evidence"], edge["source"], edge["target"],
    )):
        source, target = edge["source"], edge["target"]
        if edge["traversable"] and not routes.has_edge(source, target):
            routes.add_edge(source, target, edge=edge)
    paths = []
    blast_radius = {}
    for start, node in sorted(graph.nodes(data=True)):
        if not node["entry"]:
            continue
        shortest = nx.single_source_shortest_path(routes, start, cutoff=max_hops)
        reachable = sorted(
            target for target in shortest if target != start and graph.nodes[target]["impact"]
        )
        blast_radius[start] = {
            "score": sum(graph.nodes[target]["impact"] for target in reachable),
            "targets": reachable,
        }
        for target in reachable:
            route = shortest[target]
            edges = [routes[left][right]["edge"] for left, right in zip(route, route[1:])]
            paths.append({
                "nodes": route,
                "edges": edges,
                "impact": graph.nodes[target]["impact"],
                "conditional": any(edge["conditional"] for edge in edges),
            })
    paths.sort(key=lambda path: (-path["impact"], len(path["edges"]), path["nodes"]))
    return paths, blast_radius


def analyze(inventory: Inventory, max_hops: int = 8) -> dict:
    paths, blast_radius = find_paths(build_graph(inventory), max_hops)
    return {
        "nodes": [node.model_dump() for node in inventory.nodes.values()],
        "edges": [edge.model_dump() for edge in inventory.edges],
        "findings": [edge.model_dump() for edge in inventory.edges if edge.finding],
        "paths": paths,
        "blast_radius": blast_radius,
        "max_hops": max_hops,
    }
