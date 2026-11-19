# KubeBlast

**Cross-Boundary Cloud IAM ↔ Kubernetes RBAC ↔ GitHub Actions OIDC Attack-Graph Analyzer & Auto-Remediator.**

## Core Capabilities
1. **Multi-Surface Graph Ingestion:** Parses AWS IAM policies/roles, GCP IAM bindings, Kubernetes RBAC (`ClusterRole`, `RoleBinding`, `ServiceAccount`, `Pod` hostPath/privileged flags), GitHub Actions OIDC trust conditions, and Terraform HCL files.
2. **Escalation Pathfinder & Blast-Radius Scoring:** Computes shortest & highest-impact privilege escalation chains from unprivileged CI workflows or compromised pods to cluster-admin / cloud root accounts.
3. **Automated Least-Privilege Remediation:** Generates minimal-diff Terraform IAM policy patches and **Kyverno / OPA Rego** admission policies blocking discovered escalation paths.
4. **Interactive Attack-Path HTML Visualizer:** Outputs a standalone Cytoscape-style interactive graph + JSON/Markdown audit report.

## Run locally

Use Python 3.12 or newer.

```sh
python -m pip install '.[test]'
python -m pytest
kubeblast examples/vulnerable_lab --output /tmp/kubeblast-report
```

Pass one or more IAM exports, Terraform files, Kubernetes manifests, or directories.
KubeBlast reads AWS account authorization details, standalone IAM policy
documents, role trust documents with an associated role ARN, and GCP
getIamPolicy-style bindings. Include the GCP resource name alongside the policy
to correlate service-account grants. Terraform ingestion handles literal AWS
IAM resources, IAM policy document data blocks, and common resource references.
The example fixtures are static inputs for the analyzer.

Open `report.html` directly in a browser and use the path selector or select
a node to inspect relationships. `report.json` includes edge evidence, the
shortest path to each reachable impact target, and each entry point's blast
radius. The score sums the impact of distinct reachable targets within
`--max-hops` (default 8). Paths are ordered by target impact and then hop
count. `report.md` is the text audit.

## Interpret findings and review remediation

Graph reachability is an estimate based on the supplied files. Dashed edges
indicate conditional access or access that depends on runtime prerequisites.
PassRole is reported as a finding without traversal because it also needs a
compatible service and a service API grant. AWS session policies, boundaries,
organization policies, GCP conditions and custom roles, Terraform modules and
dynamic expressions, and Kubernetes aggregated roles or external admission
configuration can change effective access. Keep inputs scoped to a single
Kubernetes cluster.

The remediation directory contains a Terraform policy editing template, a
Kyverno ClusterPolicy in audit mode, and Rego v1 admission rules. The Terraform
template preserves unselected statements and lets reviewers tighten OIDC
subjects, replace or remove IAM statements, and remove selected GCP binding
members. Review the resulting policies against required access and existing
resource addresses before applying them.
