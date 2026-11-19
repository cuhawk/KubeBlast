import json
from pathlib import Path

import yaml

from .parsers.oidc_parser import ISSUER


def terraform_patch(findings: list[dict]) -> str:
    """Create a reviewable Terraform module for tightening existing policy documents."""
    aws = [edge for edge in findings if edge["rule"].startswith(("aws_", "github_"))]
    gcp = [edge for edge in findings if edge["rule"].startswith("gcp_")]
    if not aws and not gcp:
        return "# No cloud IAM findings.\n"
    parts = [
        "# Supply reviewed replacements for the affected identities below.",
        "# Apply the output documents at the existing policy resource addresses.",
    ]
    for edge in aws + gcp:
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
    if "k8s_token_mount" in kinds:
        add("projected-service-account-token", ["Pod"], {"foreach": [{
            "list": "request.object.spec.volumes[].projected.sources[] || `[]`",
            "pattern": {"X(serviceAccountToken)": "null"},
        }]}, [
            'some volume in object.get(input.request.object.spec, "volumes", [])',
            'some projection in object.get(object.get(volume, "projected", {}), "sources", [])',
            '"serviceAccountToken" in object.keys(projection)',
        ])
    if "k8s_privileged" in kinds:
        for field in ("containers", "initContainers", "ephemeralContainers"):
            add(f"privileged-{field.lower()}", ["Pod"], {"foreach": [{
                "list": f"request.object.spec.{field} || `[]`",
                "pattern": {"=(securityContext)": {"=(privileged)": False}},
            }]}, [
                f"some container in object.get(input.request.object.spec, {json.dumps(field)}, [])",
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
    }
    for rule, (verb, resources) in restrictions.items():
        if rule not in kinds:
            continue
        verbs = [verb, "*"] if rule != "k8s_exec" else ["create", "get", "*"]
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
    kyverno, rego = kubernetes_controls(findings)
    for name, text in {
        "iam.tf": terraform_patch(findings),
        "kyverno.yaml": kyverno,
        "kubeblast.rego": rego,
    }.items():
        (directory / name).write_text(text, encoding="utf-8")
