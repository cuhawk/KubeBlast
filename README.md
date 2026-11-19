# KubeBlast

**Cross-Boundary Cloud IAM ↔ Kubernetes RBAC ↔ GitHub Actions OIDC Attack-Graph Analyzer & Auto-Remediator.**

## Core Capabilities
1. **Multi-Surface Graph Ingestion:** Parses AWS IAM policies/roles, GCP IAM bindings, Kubernetes RBAC (`ClusterRole`, `RoleBinding`, `ServiceAccount`, `Pod` hostPath/privileged flags), GitHub Actions OIDC trust conditions, and Terraform HCL files.
2. **Escalation Pathfinder & Blast-Radius Scoring:** Computes shortest & highest-impact privilege escalation chains from unprivileged CI workflows or compromised pods to cluster-admin / cloud root accounts.
3. **Automated Least-Privilege Remediation:** Generates minimal-diff Terraform IAM policy patches and **Kyverno / OPA Rego** admission policies blocking discovered escalation paths.
4. **Interactive Attack-Path HTML Visualizer:** Outputs a standalone Cytoscape-style interactive graph + JSON/Markdown audit report.
