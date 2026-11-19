import json
from pathlib import Path

import hcl2
import pytest
import yaml

from kubeblast.cli import main
from kubeblast.graph import analyze, build_graph, read_inventory
from kubeblast.models import Edge, Inventory, Principal
from kubeblast.parsers.aws_iam import AWSParser, document, matches
from kubeblast.parsers.k8s_rbac import KubernetesParser, permits
from kubeblast.parsers.oidc_parser import ISSUER, parse_trust
from kubeblast.remediate import kubernetes_controls, terraform_patch
from kubeblast.visualizer import render_html, render_markdown

LAB = Path(__file__).resolve().parents[1] / "examples" / "vulnerable_lab"
CI = "arn:aws:iam::111122223333:role/ci"
DEPLOY = "arn:aws:iam::111122223333:role/deploy"
OIDC = "github:repo:example/demo:*"
POD = "k8s:workload:demo:Pod:runner"
SA = "k8s:sa:demo:runner"
ADMIN = "aws:admin-capability"


@pytest.fixture(scope="module")
def lab():
    return read_inventory([LAB])


@pytest.mark.parametrize(("source", "target", "rule"), [
    (OIDC, CI, "github_oidc"),
    (CI, DEPLOY, "aws_assume_role"),
    (DEPLOY, ADMIN, "aws_admin"),
    (POD, SA, "k8s_token_mount"),
    (SA, DEPLOY, "aws_irsa"),
    (SA, "k8s:role:ClusterRole:*:cluster-admin", "k8s_binding"),
    (SA, "gcp:sa:ci@demo-project.iam.gserviceaccount.com", "gcp_workload_identity"),
    ("aws:terraform:aws_iam_user:fixture", "aws:secret:*", "aws_secret_read"),
])
def test_graph_relationships(lab, source, target, rule):
    assert any(edge["rule"] == rule for edge in build_graph(lab)[source][target].values())


@pytest.mark.parametrize(("start", "target", "length"), [
    (OIDC, ADMIN, 3),
    (POD, ADMIN, 3),
    (POD, "gcp:grant:projects/demo-project:roles/owner", 3),
    (POD, "k8s:role:ClusterRole:*:cluster-admin", 2),
])
def test_shortest_routes(lab, start, target, length):
    report = analyze(lab)
    route = next(p for p in report["paths"] if p["nodes"][0] == start and p["nodes"][-1] == target)
    assert len(route["edges"]) == length
    assert len(set(route["nodes"])) == length + 1
    assert target in report["blast_radius"][start]["targets"]


def test_cutoff(lab):
    assert ADMIN not in analyze(lab, 2)["blast_radius"][OIDC]["targets"]


def test_zero_cutoff(lab):
    with pytest.raises(ValueError, match="positive"):
        analyze(lab, 0)


def test_ranking_and_score(lab):
    report = analyze(lab)
    assert [p["impact"] for p in report["paths"]] == sorted(
        (p["impact"] for p in report["paths"]), reverse=True
    )
    assert report["blast_radius"][OIDC] == {"score": 17, "targets": [ADMIN, "aws:secret:*"]}


@pytest.mark.parametrize(("patterns", "value", "result"), [
    ("sts:*", "sts:assumerole", True),
    ("arn:aws:iam::*:role/deploy", DEPLOY, True),
    ("arn:aws:iam::*:role/[cd]", DEPLOY, False),
    (["p?d"], "pod", True),
])
def test_aws_wildcards(patterns, value, result):
    assert matches(value, patterns) is result


def test_jsonencode():
    policy = document('${jsonencode({"Statement":{"Effect":"Deny"}})}')
    assert policy["Statement"]["Effect"] == "Deny"


def test_aws_deny_and_missing_trust():
    inventory = Inventory()
    parser = AWSParser(inventory)
    user = "arn:aws:iam::111122223333:user/test"
    allow = {"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "*"}
    deny = {"Effect": "Deny", "Action": "sts:AssumeRole", "Resource": CI}
    parser.ingest({"RoleDetailList": [
        {"Arn": CI, "AssumeRolePolicyDocument": {"Statement": {
            "Effect": "Allow", "Action": "sts:AssumeRole", "Principal": {"AWS": user}
        }}},
        {"Arn": DEPLOY},
    ]}, "roles.json")
    parser.ingest({"PrincipalArn": user, "Statement": [allow, deny]}, "policy.json")
    parser.finish()
    assert not inventory.edges


@pytest.mark.parametrize(("subject", "audience", "finding"), [
    ("repo:org/name:ref:refs/heads/main", "sts.amazonaws.com", False),
    ("repo:org/name:*", "sts.amazonaws.com", True),
    ("repo:org/name:environment:release", None, True),
])
def test_oidc(subject, audience, finding):
    inventory = Inventory()
    inventory.add(Principal(id=CI, label=CI))
    parse_trust([{
        "Effect": "Allow", "Action": "sts:AssumeRoleWithWebIdentity",
        "Principal": {"Federated": f"arn:aws:iam::111122223333:oidc-provider/{ISSUER}"},
        "Condition": {"StringEquals": {f"{ISSUER}:sub": subject, f"{ISSUER}:aud": audience}},
    }], CI, inventory, "trust.json")
    assert inventory.edges[0].finding is finding


@pytest.mark.parametrize(("resource", "group", "allowed"), [
    ("pods/exec", "", True),
    ("pods", "", False),
    ("pods/exec", "apps", False),
])
def test_rbac_subresource(resource, group, allowed):
    rule = {"verbs": ["get"], "apiGroups": [""], "resources": ["*/exec"]}
    assert permits(rule, "get", resource, group) is allowed


def test_namespaced_cluster_role_binding_is_not_cluster_admin():
    inventory = Inventory()
    parser = KubernetesParser(inventory)
    parser.ingest({
        "kind": "RoleBinding", "metadata": {"name": "example", "namespace": "other"},
        "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"},
        "subjects": [{"kind": "User", "name": "user"}],
    }, "role.yaml")
    parser.finish()
    assert inventory.edges[0].scope == "other"
    assert not analyze(inventory)["paths"]


@pytest.mark.parametrize(("pod_setting", "projected", "mount"), [
    (None, False, False),
    (True, False, True),
    (False, True, True),
])
def test_token_inheritance(pod_setting, projected, mount):
    inventory = Inventory()
    parser = KubernetesParser(inventory)
    parser.ingest({
        "kind": "ServiceAccount", "metadata": {"name": "runner"},
        "automountServiceAccountToken": False,
    }, "sa.yaml")
    spec = {"serviceAccountName": "runner"}
    if pod_setting is not None:
        spec["automountServiceAccountToken"] = pod_setting
    if projected:
        spec["volumes"] = [{"projected": {"sources": [{"serviceAccountToken": {"path": "token"}}]}}]
    parser.ingest({"kind": "Pod", "metadata": {"name": "runner"}, "spec": spec}, "pod.yaml")
    parser.finish()
    assert any(edge.rule == "k8s_token_mount" for edge in inventory.edges) is mount


def test_invalid_input(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("[")
    with pytest.raises(ValueError, match="bad.json"):
        read_inventory([bad])


def test_hcl(lab):
    source = terraform_patch(analyze(lab)["findings"])
    data = hcl2.loads(source)
    assert any("github_oidc_trust_statement" in output for output in data["output"])
    assert any("gcp_binding_members" in output for output in data["output"])


def test_kubernetes_remediation(lab):
    kyverno, rego = kubernetes_controls(analyze(lab)["findings"])
    policy = yaml.safe_load(kyverno)
    assert policy["kind"] == "ClusterPolicy"
    rules = {rule["name"] for rule in policy["spec"]["rules"]}
    assert {"k8s-hostpath", "k8s-exec", "k8s-token-mount", "cluster-admin-binding"} <= rules
    assert "import rego.v1" in rego
    assert "deny contains" in rego


def test_html_script_injection():
    node = Principal(id="entry", label="</script><script>unsafe()</script>", entry=True)
    inventory = Inventory(nodes={node.id: node})
    report = analyze(inventory)
    html = render_html(report)
    data = html.split('<script id="report" type="application/json">', 1)[1].split("</script>", 1)[0]
    assert "unsafe()</script>" not in html
    assert json.loads(data) == report


def test_markdown(lab):
    report = render_markdown(analyze(lab))
    assert "## Findings" in report
    assert OIDC in report


def test_edge_requires_evidence():
    with pytest.raises(ValueError):
        Edge(source="a", target="b", rule="test")


def test_cli(tmp_path):
    assert main([str(LAB), "--output", str(tmp_path)]) == 0
    assert {path.name for path in tmp_path.iterdir()} == {
        "report.json", "report.md", "report.html", "remediation"
    }
    assert len(json.loads((tmp_path / "report.json").read_text())["paths"]) >= 4
    assert (tmp_path / "remediation" / "iam.tf").is_file()
