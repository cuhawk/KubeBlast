# Codex Cloud Implementation Specification: KubeBlast
Build a complete Python 3.12+ Cloud-Native & Kubernetes Security tool (`src/kubeblast/`) using `pydantic>=2`, `pyyaml`, `networkx`, `jinja2`:
- `src/kubeblast/models.py`: Typed node/edge schema (`Principal`, `IAMRole`, `K8sServiceAccount`, `K8sRole`, `PodWorkload`, `GitHubOIDC`, `CloudSecret`).
- `src/kubeblast/parsers/`: Modular parsers for AWS IAM JSON & Terraform HCL (`aws_iam.py`), GCP IAM (`gcp_iam.py`), Kubernetes YAML manifests (`k8s_rbac.py`), and GitHub Actions OIDC trust policies (`oidc_parser.py`).
- `src/kubeblast/graph.py`: NetworkX attack-graph builder, privilege-escalation rule engine (IRSA/Workload Identity abuse, `iam:PassRole`, `sts:AssumeRole` cycles, wildcard OIDC `sub`, K8s `escalate`/`bind`/`impersonate`, `pods/exec`, `hostPath`, `automountServiceAccountToken`), and blast-radius scorer.
- `src/kubeblast/remediate.py`: Generates concrete least-privilege Terraform HCL diffs, Kyverno `ClusterPolicy` YAML, and OPA Rego rules for every detected attack edge.
- `src/kubeblast/visualizer.py`: Exports a self-contained zero-backend interactive HTML attack-graph report.
- `examples/vulnerable_lab/`: Realistic multi-cloud AWS + K8s + GitHub OIDC vulnerable infrastructure fixtures.
- `tests/`: 25+ `pytest` tests verifying graph construction, multi-hop escalation path discovery, remediation generation, and HTML/JSON report validity.
- `.github/workflows/ci.yml`: Automated pytest CI workflow.
