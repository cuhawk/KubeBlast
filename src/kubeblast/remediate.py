from collections import defaultdict, deque
import json
from pathlib import Path

import yaml

from .parsers.oidc_parser import ISSUER


def terraform_patch(findings: list[dict]) -> str:
    """Create a reviewable Terraform module for tightening existing policy documents."""
    aws = [edge for edge in findings if edge["rule"].startswith(("aws_", "github_"))]
    gcp = [edge for edge in findings if edge["rule"].startswith("gcp_")]
    azure = [edge for edge in findings if edge["rule"].startswith("azure_")]
    if not aws and not gcp and not azure:
        return "# No cloud IAM findings.\n"
    parts = [
        "# Supply reviewed replacements for the affected identities below.",
        "# Apply the output documents at the existing policy resource addresses.",
    ]
    for edge in aws + gcp + azure:
        evidence = json.dumps(edge["evidence"], ensure_ascii=True)
        parts.append(f"# {edge['rule']} in {evidence}")
    if aws:
        parts.append('''
variable "aws_policy_documents" {
  description = "Original AWS policy statements keyed by existing policy address"
  type        = any
  default     = {}
}

variable "aws_replacement_statements" {
  description = "Per-policy complete, approved replacements for the selected statement indices"
  type        = any
  default     = {}
}

output "aws_policy_documents" {
  value = {
    for address, statements in var.aws_policy_documents : address => jsonencode({
      Version = "2012-10-17"
      Statement = [
        for index, statement in statements :
        try(var.aws_replacement_statements[address][tostring(index)], statement)
        if try(var.aws_replacement_statements[address][tostring(index)] != null, true)
      ]
    })
  }
}
''')
    if any(edge["rule"] == "github_oidc" for edge in aws):
        parts.append(f'''
variable "github_oidc_provider_arn" {{
  type = string
}}

variable "github_oidc_subjects" {{
  type = set(string)
  validation {{
    condition = length(var.github_oidc_subjects) > 0 && alltrue([
      for subject in var.github_oidc_subjects :
      startswith(subject, "repo:") && length(regexall("[*?]", subject)) == 0
    ])
    error_message = "Supply at least one exact GitHub repository subject without wildcards."
  }}
}}

output "github_oidc_trust_statement" {{
  value = {{
    Effect    = "Allow"
    Action    = "sts:AssumeRoleWithWebIdentity"
    Principal = {{ Federated = var.github_oidc_provider_arn }}
    Condition = {{
      StringEquals = {{
        "{ISSUER}:aud" = "sts.amazonaws.com"
        "{ISSUER}:sub" = sort(tolist(var.github_oidc_subjects))
      }}
    }}
  }}
}}
''')
    if gcp:
        parts.append('''
variable "gcp_binding_removals" {
  description = "Reviewed members to remove, keyed by full binding address"
  type        = map(set(string))
  default     = {}
}

variable "gcp_binding_members" {
  type    = map(set(string))
  default = {}
}

output "gcp_binding_members" {
  value = {
    for address, members in var.gcp_binding_members : address =>
    setsubtract(members, lookup(var.gcp_binding_removals, address, toset([])))
  }
}
''')
    return "\n".join(parts) + "\n"


def kubernetes_controls(findings: list[dict]) -> tuple[str, str]:
    kinds = {edge["rule"] for edge in findings}
    rules = []
    rego = ["package kubeblast", "", "import rego.v1", ""]
    pod_controls = {
        "k8s_hostpath": (
            {"volumes": [{"X(hostPath)": "null"}]},
            ["some volume in object.get(input.request.object.spec, \"volumes\", [])",
             '\"hostPath\" in object.keys(volume)'],
        ),
        "k8s_token_mount": (
            {"automountServiceAccountToken": False},
            ['object.get(input.request.object.spec, "automountServiceAccountToken", true) != false'],
        ),
    }

    def add(name, resources, validation, body):
        message = f"KubeBlast blocks {name.replace('-', ' ')}"
        rules.append({
            "name": name,
            "match": {"any": [{"resources": {"kinds": resources}}]},
            "validate": {"message": message, **validation},
        })
        rego.extend([f"deny contains {json.dumps(message)} if {{",
                     f"    input.request.kind.kind in {json.dumps(resources)}",
                     *[f"    {line}" for line in body], "}", ""])

    for rule, (pattern, body) in pod_controls.items():
        if rule in kinds:
            add(rule.replace("_", "-"), ["Pod"], {"pattern": {"spec": pattern}}, body)
    if "k8s_hostpath" in kinds:
        add("k8s-hostpath-daemonset", ["DaemonSet"], {"foreach": [{
            "list": "request.object.spec.template.spec.volumes || `[]`",
            "pattern": {"X(hostPath)": "null"},
        }]}, [
            'some volume in object.get(input.request.object.spec.template.spec, "volumes", [])',
            '"hostPath" in object.keys(volume)',
        ])
    if "k8s_token_mount" in kinds:
        add("projected-service-account-token", ["Pod"], {"foreach": [{
            "list": "request.object.spec.volumes[].projected.sources[] || `[]`",
            "pattern": {"X(serviceAccountToken)": "null"},
        }]}, [
            'some volume in object.get(input.request.object.spec, "volumes", [])',
            'some projection in object.get(object.get(volume, "projected", {}), "sources", [])',
            '"serviceAccountToken" in object.keys(projection)',
        ])
    if kinds & {"k8s_privileged", "k8s_privileged_daemonset"}:
        for field in ("containers", "initContainers", "ephemeralContainers"):
            for resource, prefix in (("Pod", "spec"), ("DaemonSet", "spec.template.spec")):
                if resource == "DaemonSet" and "k8s_privileged_daemonset" not in kinds:
                    continue
                add(f"privileged-{resource.lower()}-{field.lower()}", [resource], {"foreach": [{
                    "list": f"request.object.{prefix}.{field} || `[]`",
                    "pattern": {"=(securityContext)": {"=(privileged)": False}},
                }]}, [
                    f"some container in object.get(input.request.object.{prefix}, {json.dumps(field)}, [])",
                    'object.get(object.get(container, "securityContext", {}), "privileged", false)',
                ])
    if "k8s_binding" in kinds:
        add("cluster-admin-binding", ["ClusterRoleBinding"], {
            "deny": {"conditions": {"all": [{
                "key": "{{ request.object.roleRef.name }}", "operator": "Equals", "value": "cluster-admin",
            }]}}
        }, ['input.request.object.roleRef.name == "cluster-admin"'])
    restrictions = {
        "k8s_bind": ("bind", ["roles", "clusterroles"]),
        "k8s_escalate": ("escalate", ["roles", "clusterroles"]),
        "k8s_impersonate": ("impersonate", ["serviceaccounts", "users", "groups"]),
        "k8s_exec": ("create", ["pods/exec", "*/exec"]),
        "k8s_node_proxy": ("get", ["nodes/proxy", "*/proxy"]),
    }
    for rule, (verb, resources) in restrictions.items():
        if rule not in kinds:
            continue
        verbs = ["create", "get", "*"] if rule in {"k8s_exec", "k8s_node_proxy"} else [verb, "*"]
        resources = [*resources, "*"]
        groups = ["rbac.authorization.k8s.io", "*"] if rule in {"k8s_bind", "k8s_escalate"} else ["", "*"]
        add(rule.replace("_", "-"), ["Role", "ClusterRole"], {"foreach": [{
            "list": "request.object.rules || `[]`",
            "deny": {"conditions": {"all": [
                {"key": "{{ element.verbs }}", "operator": "AnyIn", "value": verbs},
                {"key": "{{ element.resources || `[]` }}", "operator": "AnyIn", "value": resources},
                {"key": "{{ element.apiGroups || `[]` }}", "operator": "AnyIn", "value": groups},
            ]}},
        }]}, [
            "some rule in input.request.object.rules",
            f"some verb in rule.verbs; verb in {json.dumps(verbs)}",
            f"some resource in rule.resources; resource in {json.dumps(resources)}",
            f"some group in rule.apiGroups; group in {json.dumps(groups)}",
        ])

    if not rules:
        return "# No Kubernetes admission controls generated.\n", "\n".join(rego)
    policy = {
        "apiVersion": "kyverno.io/v1", "kind": "ClusterPolicy",
        "metadata": {"name": "kubeblast-restrict-escalation"},
        "spec": {"background": True, "rules": rules},
    }
    for rule in rules:
        rule["validate"]["failureAction"] = "Audit"
    return yaml.safe_dump(policy, sort_keys=False), "\n".join(rego)


def write_remediation(report: dict, directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    findings = report["findings"]
    cut = minimum_cut_set(report)
    recommendations = findings + [edge for edge in cut["edges"] if edge not in findings]
    kyverno, rego = kubernetes_controls(recommendations)
    for name, text in {
        "iam.tf": terraform_patch(recommendations),
        "kyverno.yaml": kyverno,
        "kubeblast.rego": rego,
        "validating-policy.yaml": validating_policy(recommendations),
        "cut-set.json": json.dumps(cut, indent=2) + "\n",
    }.items():
        (directory / name).write_text(text, encoding="utf-8")


def minimum_cut_set(report: dict, minimum_impact: int = 7) -> dict:
    """Find a minimum-cardinality cut of all remediable entry/target pairs."""
    edges = sorted(report["edges"], key=lambda edge: (
        edge["source"], edge["target"], edge["rule"], edge["scope"],
        edge["evidence"], edge["conditional"], edge["finding"], edge["traversable"],
    ))
    entries = sorted(node["id"] for node in report["nodes"] if node["entry"])
    targets = {node["id"] for node in report["nodes"] if node["impact"] >= minimum_impact}
    adjustable = {
        index for index, edge in enumerate(edges)
        if edge["rule"].startswith(("aws_", "github_", "gcp_", "azure_"))
        or edge["rule"] in {
            "k8s_binding", "k8s_bind", "k8s_escalate", "k8s_impersonate",
            "k8s_exec", "k8s_workload_write", "k8s_node_proxy",
        }
    }
    outgoing = defaultdict(list)
    for index, edge in enumerate(edges):
        if edge["traversable"]:
            outgoing[edge["source"]].append((edge["target"], index))

    def reachable(start, removed):
        queue = deque([(start, 0)])
        predecessors = {start: (None, None)}
        while queue:
            node, depth = queue.popleft()
            if depth == report["max_hops"]:
                continue
            for target, index in outgoing[node]:
                if index not in removed and target not in predecessors:
                    predecessors[target] = node, index
                    queue.append((target, depth + 1))
        return predecessors

    fixed = {
        start: (targets & reachable(start, adjustable).keys()) - {start}
        for start in entries
    }

    def witness(removed):
        for start in entries:
            predecessors = reachable(start, removed)
            hit = (targets & predecessors.keys()) - fixed[start] - {start}
            if not hit:
                continue
            node = min(hit)
            candidates = []
            while node != start:
                node, index = predecessors[node]
                if index in adjustable:
                    candidates.append(index)
            return candidates
        return None

    # Every feasible solution must remove at least one adjustable edge from
    # the current witness. Branch on those edges and retain the best solution.
    pending = [frozenset()]
    seen = set()
    best = None
    while pending:
        removed = pending.pop()
        if removed in seen or (best is not None and len(removed) >= len(best)):
            continue
        seen.add(removed)
        candidates = witness(removed)
        if candidates is None:
            best = tuple(sorted(removed))
            continue
        if best is not None:
            # Edge-disjoint candidate sets each require a separate removal.
            blocked = removed | set(candidates)
            lower_bound = len(removed) + 1
            while lower_bound < len(best) and (additional := witness(blocked)) is not None:
                blocked |= set(additional)
                lower_bound += 1
            if lower_bound >= len(best):
                continue
        pending.extend(removed | {index} for index in reversed(sorted(candidates)))

    return {
        "minimum_impact": minimum_impact,
        "max_hops": report["max_hops"],
        "complete": not any(fixed.values()),
        "edges": [edges[index] for index in best],
        "unremediable_pairs": [
            {"entry": start, "target": target} for start in entries for target in sorted(fixed[start])
        ],
    }


def validating_policy(findings: list[dict]) -> str:
    """Render the same admission checks as CEL-based Kyverno policies."""
    checks = yaml.safe_load(kubernetes_controls(findings)[0])
    if checks is None:
        return "# No Kubernetes admission controls generated.\n"

    def expression(validate):
        if "deny" in validate:
            return "object.roleRef.name != 'cluster-admin'"
        if "pattern" in validate:
            spec = validate["pattern"]["spec"]
            if "volumes" in spec:
                return "!has(object.spec.volumes) || object.spec.volumes.all(v, !has(v.hostPath))"
            return "has(object.spec.automountServiceAccountToken) && !object.spec.automountServiceAccountToken"
        loop = validate["foreach"][0]
        if "deny" in loop:
            conditions = loop["deny"]["conditions"]["all"]
            verbs, resources, groups = (json.dumps(condition["value"]) for condition in conditions)
            return (
                f"!object.rules.exists(r, r.verbs.exists(v, v in {verbs}) && "
                f"has(r.resources) && r.resources.exists(s, s in {resources}) && "
                f"has(r.apiGroups) && r.apiGroups.exists(g, g in {groups}))"
            )
        if "X(hostPath)" in loop.get("pattern", {}):
            return (
                "!has(object.spec.template.spec.volumes) || "
                "object.spec.template.spec.volumes.all(v, !has(v.hostPath))"
            )
        if "projected" in loop["list"]:
            return (
                "!has(object.spec.volumes) || object.spec.volumes.all(v, !has(v.projected) || "
                "v.projected.sources.all(s, !has(s.serviceAccountToken)))"
            )
        field = loop["list"].split(" || ", 1)[0].removeprefix("request.")
        return (
            f"!has({field}) || {field}.all(c, !has(c.securityContext) || "
            "!has(c.securityContext.privileged) || !c.securityContext.privileged)"
        )

    resources = {
        "Pod": ("", "v1", "pods"),
        "DaemonSet": ("apps", "v1", "daemonsets"),
        "ClusterRoleBinding": ("rbac.authorization.k8s.io", "v1", "clusterrolebindings"),
        "Role": ("rbac.authorization.k8s.io", "v1", "roles"),
        "ClusterRole": ("rbac.authorization.k8s.io", "v1", "clusterroles"),
    }
    policies = []
    for rule in checks["spec"]["rules"]:
        kinds = rule["match"]["any"][0]["resources"]["kinds"]
        validate = rule["validate"]
        policies.append({
            "apiVersion": "policies.kyverno.io/v1",
            "kind": "ValidatingPolicy",
            "metadata": {"name": f"kubeblast-{rule['name']}"},
            "spec": {
                "validationActions": ["Audit"],
                "matchConstraints": {"resourceRules": [
                    {"apiGroups": [group], "apiVersions": [version],
                     "operations": ["CREATE", "UPDATE"], "resources": [resource]}
                    for group, version, resource in (resources[kind] for kind in kinds)
                ]},
                "validations": [{"expression": expression(validate), "message": validate["message"]}],
            },
        })
    return yaml.safe_dump_all(policies, sort_keys=False)
