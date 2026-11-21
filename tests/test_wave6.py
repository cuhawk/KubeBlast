import json
import shutil
import subprocess
from itertools import combinations
from pathlib import Path

import pytest
import yaml

from kubeblast.cli import main
from kubeblast.graph import analyze, read_inventory
from kubeblast.models import Inventory, Node
from kubeblast.parsers.aws_iam import AWSParser
from kubeblast.parsers.azure_entra import parse_entra
from kubeblast.parsers.gcp_iam import parse_gcp
from kubeblast.parsers.k8s_rbac import KubernetesParser
from kubeblast.remediate import kubernetes_controls, minimum_cut_set, validating_policy

ROOT = Path(__file__).resolve().parents[1]
ROLE = "arn:aws:iam::111122223333:role/test"
EKS = "oidc.eks.us-east-1.amazonaws.com/id/1234"
ACCOUNT = "k8s:sa:demo:runner"
SUBJECT = "system:serviceaccount:demo:runner"
POOL = "iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/project.svc.id.goog"


@pytest.mark.parametrize("audience,subject,operator,expected", [
    ("sts.amazonaws.com", SUBJECT, "StringEquals", True),
    (["invalid", "sts.amazonaws.com"], SUBJECT, "StringEquals", True),
    ("other.example", SUBJECT, "StringEquals", False),
    ("sts.amazonaws.com", SUBJECT + "2", "StringEquals", False),
    ("sts.amazonaws.com", "system:serviceaccount:demo:*", "StringLike", True),
    ("sts.amazonaws.com", "system:serviceaccount:other:*", "StringLike", False),
    ("sts.amazonaws.com", "system:serviceaccount:demo:*", "StringEquals", False),
    ("sts.amazonaws.com", [SUBJECT, "another"], "StringEquals", True),
])
def test_irsa_matches_subject_and_audience(audience, subject, operator, expected):
    inventory = Inventory()
    parser = AWSParser(inventory)
    conditions = {"StringEquals": {f"{EKS}:aud": audience}}
    conditions.setdefault(operator, {})[f"{EKS}:sub"] = subject
    parser.ingest({"RoleDetailList": [{
        "Arn": ROLE,
        "AssumeRolePolicyDocument": {"Statement": {
            "Effect": "Allow", "Action": "sts:AssumeRoleWithWebIdentity",
            "Principal": {"Federated": f"arn:aws:iam::111122223333:oidc-provider/{EKS}"},
            "Condition": conditions,
        }},
    }]}, "roles.json")
    parser.finish([(ACCOUNT, ROLE, SUBJECT)])
    assert bool(inventory.edges) is expected


@pytest.mark.parametrize("association,actions,principal,expected", [
    ("association", ["sts:AssumeRole", "sts:TagSession"], "pods.eks.amazonaws.com", True),
    ("associations", ["sts:*"], "pods.eks.amazonaws.com", True),
    ("association", ["sts:AssumeRole"], "pods.eks.amazonaws.com", False),
    ("association", ["sts:TagSession"], "pods.eks.amazonaws.com", False),
    ("association", ["sts:*"], "ec2.amazonaws.com", False),
    ("none", ["sts:*"], "pods.eks.amazonaws.com", False),
])
def test_eks_association_requires_both_trust_actions(association, actions, principal, expected):
    inventory = Inventory()
    parser = AWSParser(inventory)
    value = {"roleArn": ROLE, "namespace": "demo", "serviceAccount": "runner"}
    parser.ingest({association: [value] if association == "associations" else value}, "eks.json")
    parser.ingest({"RoleDetailList": [{
        "Arn": ROLE,
        "AssumeRolePolicyDocument": {"Statement": {
            "Effect": "Allow", "Action": actions, "Principal": {"Service": principal},
        }},
    }]}, "iam.json")
    parser.finish()
    assert bool(inventory.edges) is expected
    if expected:
        edge, = inventory.edges
        assert (edge.source, edge.target, edge.rule) == (ACCOUNT, ROLE, "aws_eks_pod_identity")
        assert edge.conditional and edge.evidence == "eks.json"


@pytest.mark.parametrize("member,expected", [
    (f"principal://{POOL}/subject/ns/demo/sa/runner", True),
    (f"principalSet://{POOL}/namespace/demo", True),
    (f"principalSet://{POOL}/namespace/other", False),
    (f"principal://{POOL}/subject/ns/demo/sa/helper", False),
    ("serviceAccount:runner@project.iam.gserviceaccount.com", False),
    ("deleted:serviceAccount:runner@project.iam.gserviceaccount.com", False),
])
def test_gke_direct_workload_federation(member, expected):
    inventory = Inventory()
    KubernetesParser(inventory).account("demo", "runner")
    parse_gcp({"name": "projects/p", "bindings": [{
        "role": "roles/owner", "members": [member],
    }]}, inventory, "gcp.json")
    assert any(edge.source == ACCOUNT and edge.rule == "gcp_workload_identity"
               for edge in inventory.edges) is expected


@pytest.mark.parametrize("issuer,subject,audiences,annotation,expected", [
    ("https://issuer.example/", SUBJECT, ["api://AzureADTokenExchange"], "app", True),
    ("https://issuer.example/", SUBJECT, ["api://AzureADTokenExchange"], None, True),
    ("https://issuer.example/", SUBJECT, ["api://AzureADTokenExchange"], "other", False),
    ("http://issuer.example/", SUBJECT, ["api://AzureADTokenExchange"], "app", False),
    ("https://issuer.example/?redirect=x", SUBJECT, ["api://AzureADTokenExchange"], "app", False),
    ("https://issuer.example/", SUBJECT, ["other"], "app", False),
    ("https://issuer.example/", "repo:org/name:*", ["api://AzureADTokenExchange"], "app", False),
])
def test_entra_validates_credential(issuer, subject, audiences, annotation, expected):
    inventory = Inventory()
    parse_entra({"clientId": "app", "federatedIdentityCredentials": [{
        "properties": {"issuer": issuer, "subject": subject, "audiences": audiences},
    }]}, inventory, "azure.json", {("demo", "runner"): annotation})
    assert bool(inventory.edges) is expected
    if expected:
        edge, = inventory.edges
        assert (edge.source, edge.target, edge.rule, edge.scope) == (
            ACCOUNT, "azure:identity:app", "azure_entra_federated", issuer,
        )


@pytest.mark.parametrize("profile,kind,reachable", [
    ("restricted", "DaemonSet", False),
    ("baseline", "DaemonSet", False),
    ("privileged", "DaemonSet", True),
    (None, "DaemonSet", True),
    ("restricted", "Pod", True),
    ("baseline", "Pod", True),
])
def test_pod_security_enforcement_and_existing_pods(profile, kind, reachable):
    inventory = Inventory()
    parser = KubernetesParser(inventory)
    if profile:
        parser.ingest({"kind": "Namespace", "metadata": {
            "name": "demo", "labels": {"pod-security.kubernetes.io/enforce": profile},
        }}, "namespace.yaml")
    spec = {
        "containers": [{"securityContext": {"privileged": True}}],
        "volumes": [{"hostPath": {"path": "/test"}}],
    }
    parser.ingest({
        "kind": kind, "metadata": {"name": "test", "namespace": "demo"},
        "spec": spec if kind == "Pod" else {"template": {"spec": spec}},
    }, "workload.yaml")
    parser.finish()
    paths = analyze(inventory)["paths"]
    assert bool(paths) is reachable
    assert {edge.rule for edge in inventory.edges} >= {
        "k8s_hostpath", "k8s_privileged" if kind == "Pod" else "k8s_privileged_daemonset",
    }
    assert any(edge.rule == "k8s_podsecurity_enforced"
               for edge in inventory.edges) is (profile in {"restricted", "baseline"})


@pytest.mark.parametrize("scope,verb,resource,api_group,expected", [
    ("*", "get", "nodes/proxy", "", True),
    ("*", "create", "nodes/proxy", "", True),
    ("*", "get", "*/proxy", "", True),
    ("*", "*", "*", "*", True),
    ("demo", "get", "nodes/proxy", "", False),
    ("*", "get", "nodes", "", False),
    ("*", "get", "nodes/proxy", "apps", False),
    ("*", "list", "nodes/proxy", "", False),
])
def test_node_proxy_permissions(scope, verb, resource, api_group, expected):
    inventory = Inventory()
    parser = KubernetesParser(inventory)
    parser.permissions("role", {
        "verbs": [verb], "resources": [resource], "apiGroups": [api_group],
        "resourceNames": ["worker-a"],
    }, scope, {}, "rbac.yaml")
    assert any(edge.target == "k8s:node-proxy:worker-a" for edge in inventory.edges) is expected


def cut_inventory(pairs):
    inventory = Inventory()
    for name in {item for edge in pairs for item in edge[:2]}:
        inventory.add(Node(id=name, label=name, kind="test",
                           impact=8 if name.startswith("target") else 0,
                           entry=name.startswith("entry")))
    for index, (left, right, rule) in enumerate(pairs):
        inventory.link(left, right, rule, f"{index}.json")
    return inventory


@pytest.mark.parametrize("pairs,hops,expected_size", [
    ([("entry", "a", "gcp_binding"), ("a", "target", "gcp_binding")], 2, 1),
    ([("entry", "a", "gcp_binding"), ("a", "target", "gcp_binding")], 1, 0),
    ([("entry", "target", "gcp_binding"), ("entry", "target", "aws_admin")], 1, 2),
    ([("entry", "a", "gcp_binding"), ("entry", "b", "gcp_binding"),
      ("a", "z", "k8s_token_mount"), ("b", "z", "k8s_token_mount"),
      ("z", "target", "aws_admin")], 5, 1),
    ([("entry1", "a", "k8s_token_mount"), ("entry2", "a", "k8s_token_mount"),
      ("a", "target1", "aws_admin"), ("a", "target2", "k8s_binding")], 8, 2),
    ([("entry", "a", "k8s_token_mount"), ("a", "b", "aws_irsa"),
      ("b", "a", "gcp_binding"), ("b", "target", "aws_admin")], 3, 1),
])
def test_minimum_cut_against_brute_force(pairs, hops, expected_size):
    inventory = cut_inventory(pairs)
    report = analyze(inventory, hops)
    plan = minimum_cut_set(report)
    assert plan["complete"]
    assert len(plan["edges"]) == expected_size
    assert minimum_cut_set({**report, "edges": report["edges"][::-1]}) == plan
    for count in range(expected_size):
        candidates = [edge for edge in inventory.edges if edge.rule != "k8s_token_mount"]
        for combination in combinations(candidates, count):
            remaining = [edge for edge in inventory.edges if edge not in combination]
            assert analyze(Inventory(nodes=inventory.nodes, edges=remaining), hops)["paths"]
    surviving = [edge for edge in inventory.edges if edge.model_dump() not in plan["edges"]]
    assert not analyze(Inventory(nodes=inventory.nodes, edges=surviving), hops)["paths"]


def test_cut_reports_fixed_paths_and_solves_other_pairs():
    inventory = cut_inventory([
        ("entry", "target-fixed", "k8s_hostpath"),
        ("entry", "target-fixable", "k8s_binding"),
        ("entry", "target-observation", "aws_pass_role"),
    ])
    inventory.edges[-1].traversable = False
    cut = minimum_cut_set(analyze(inventory))
    assert not cut["complete"]
    assert cut["unremediable_pairs"] == [{"entry": "entry", "target": "target-fixed"}]
    assert [edge["target"] for edge in cut["edges"]] == ["target-fixable"]


def test_sarif_cli_contains_evidence_and_code_flows(tmp_path):
    target = ROOT / "examples" / "wave6" / "vulnerable"
    assert main([str(target), "--output", str(tmp_path), "--format", "sarif"]) == 0
    sarif = json.loads((tmp_path / "report.sarif").read_text())
    assert sarif["version"] == "2.1.0"
    run, = sarif["runs"]
    assert {result["ruleId"] for result in run["results"]} == {
        rule["id"] for rule in run["tool"]["driver"]["rules"]
    }
    paths = [result for result in run["results"] if result["ruleId"] == "authorization_path"]
    assert len(paths) >= 2
    assert all(result["codeFlows"][0]["threadFlows"][0]["locations"] for result in paths)


@pytest.fixture
def admission_bundle(tmp_path):
    findings = [{"rule": rule} for rule in (
        "k8s_hostpath", "k8s_token_mount", "k8s_privileged_daemonset", "k8s_binding",
        "k8s_bind", "k8s_escalate", "k8s_impersonate", "k8s_exec", "k8s_node_proxy",
    )]
    legacy, rego = kubernetes_controls(findings)
    files = {}
    for name, content in {
        "legacy": legacy, "rego": rego, "policy": validating_policy(findings),
    }.items():
        path = tmp_path / ("bundle.rego" if name == "rego" else f"{name}.yaml")
        path.write_text(content)
        files[name] = path
    return files


def test_policy_bundle_targets_daemonsets_and_keeps_audit_mode(admission_bundle):
    policies = list(yaml.safe_load_all(admission_bundle["policy"].read_text()))
    assert all(policy["kind"] == "ValidatingPolicy" for policy in policies)
    assert all(policy["spec"]["validationActions"] == ["Audit"] for policy in policies)
    daemonset_checks = [policy for policy in policies if "daemonset" in policy["metadata"]["name"]]
    assert len(daemonset_checks) >= 3
    assert all("object.spec.template.spec" in policy["spec"]["validations"][0]["expression"]
               for policy in daemonset_checks)


def test_opa_bundle_compiles_and_checks_fixtures(admission_bundle, tmp_path):
    opa = shutil.which("opa")
    if not opa:
        pytest.skip("OPA CLI is not installed")
    rego = admission_bundle["rego"]
    subprocess.run([opa, "check", "--strict", str(rego)], check=True)
    for name in ("hardened", "vulnerable"):
        documents = yaml.safe_load_all((ROOT / "examples" / "wave6" / name / "cluster.yaml").read_text())
        role = next(document for document in documents if document["kind"] == "ClusterRole")
        payload = tmp_path / f"{name}.json"
        payload.write_text(json.dumps({"request": {"kind": {"kind": "ClusterRole"}, "object": role}}))
        result = subprocess.run([
            opa, "eval", "--format", "raw", "--data", str(rego), "--input", str(payload),
            "data.kubeblast.deny",
        ], check=True, capture_output=True, text=True)
        assert json.loads(result.stdout) == (["KubeBlast blocks k8s node proxy"] if name == "vulnerable" else [])


def test_kyverno_bundle_compiles_and_checks_fixtures(admission_bundle):
    kyverno = shutil.which("kyverno")
    if not kyverno:
        pytest.skip("Kyverno CLI is not installed")
    for name in ("hardened", "vulnerable"):
        result = subprocess.run([
            kyverno, "apply", str(admission_bundle["policy"]), "--resource",
            str(ROOT / "examples" / "wave6" / name / "cluster.yaml"), "--remove-color",
        ], capture_output=True, text=True)
        assert result.returncode == (1 if name == "vulnerable" else 0), result.stdout + result.stderr
        assert "error: 0" in result.stdout
        assert ("KubeBlast blocks k8s node proxy" in result.stdout) is (name == "vulnerable")


@pytest.mark.parametrize("fixture", ["hardened", "vulnerable"])
def test_offline_fixture_resolves_each_cloud_trust(fixture):
    inv = read_inventory([ROOT / "examples" / "wave6" / fixture])
    assert {edge.rule for edge in inv.edges if edge.source == ACCOUNT} >= {
        "aws_eks_pod_identity", "gcp_workload_identity", "azure_entra_federated",
    }


def test_terraform_pod_identity_reference(tmp_path):
    path = tmp_path / "association.tf"
    path.write_text("""
data "aws_iam_policy_document" "trust" {
  statement {
    actions = ["sts:AssumeRole", "sts:TagSession"]
    principals {
      type = "Service"
      identifiers = ["pods.eks.amazonaws.com"]
    }
  }
}
resource "aws_iam_role" "test" {
  name = "test"
  assume_role_policy = data.aws_iam_policy_document.trust.json
}
resource "aws_eks_pod_identity_association" "test" {
  cluster_name = "test"
  namespace = "demo"
  service_account = "runner"
  role_arn = aws_iam_role.test.arn
}
""")
    edge, = read_inventory([path]).edges
    assert (edge.source, edge.target, edge.rule) == (
        ACCOUNT, "aws:terraform:aws_iam_role:test", "aws_eks_pod_identity",
    )


@pytest.mark.parametrize("profile,verb,expected", [
    ("privileged", "create", True), ("privileged", "patch", True),
    ("baseline", "create", False), ("restricted", "patch", False),
    ("privileged", "get", False),
])
def test_daemonset_permission_path(profile, verb, expected):
    inventory = Inventory()
    parser = KubernetesParser(inventory)
    docs = [
        {"kind": "Namespace", "metadata": {
            "name": "demo", "labels": {"pod-security.kubernetes.io/enforce": profile},
        }},
        {"kind": "Role", "metadata": {"namespace": "demo", "name": "editor"},
         "rules": [{"apiGroups": ["apps"], "resources": ["daemonsets"], "verbs": [verb]}]},
        {"kind": "RoleBinding", "metadata": {"namespace": "demo", "name": "editor"},
         "roleRef": {"name": "editor", "kind": "Role"}, "subjects": [{"kind": "User", "name": "editor"}]},
        {"kind": "DaemonSet", "metadata": {"namespace": "demo", "name": "agent"},
         "spec": {"template": {"spec": {"containers": [{"securityContext": {"privileged": True}}]}}}},
    ]
    for doc in docs:
        parser.ingest(doc, f"{doc['kind']}.yaml")
    parser.finish()
    paths = analyze(inventory)["paths"]
    assert any(path["nodes"][0] == "k8s:user:editor" for path in paths) is expected
    if expected:
        write = next(edge for edge in inventory.edges if edge.rule == "k8s_workload_write")
        assert write.evidence == "Role.yaml"
