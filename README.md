# KubeBlast

KubeBlast analyzes offline cloud IAM and Kubernetes RBAC exports, maps reachable
authorization paths, and generates remediation for review.

## Run locally

Use Python 3.12 or newer.

```sh
python -m pip install '.[test]'
python -m pytest
kubeblast examples/vulnerable_lab --output /tmp/kubeblast-report
kubeblast examples/wave6/vulnerable --format sarif --output /tmp/kubeblast-sarif
```

The default report includes interactive HTML, JSON and Markdown. SARIF 2.1.0
includes source files and code flows for authorization paths. Both formats
produce a remediation bundle. KubeBlast reports the shortest route to each
reachable impact target within `--max-hops` (default 8). Blast radius sums the
impact of distinct reachable targets.

## Supported input

Pass one or more YAML, JSON or Terraform files or directories for a single
cluster. Keep IAM and issuer exports scoped to that cluster so that Kubernetes
namespace and service account names can be correlated reliably.

- **AWS IAM** accepts account authorization details, role trust exports and
  standalone policies. Include the annotated Kubernetes ServiceAccount and the
  EKS issuer trust statement for IRSA. EKS Pod Identity accepts describe
  exports with an `association` object, arrays under `associations` containing
  `roleArn`, `namespace` and `serviceAccount`, or a literal Terraform
  `aws_eks_pod_identity_association`. Include the associated role and its trust
  policy. Terraform also supports literal IAM resources and common references.
- **GCP IAM** accepts getIamPolicy bindings with a resource name. It resolves
  GKE Workload Identity Federation service account and namespace principal
  URIs, and accepts annotated Kubernetes service accounts paired with
  service-account impersonation bindings.
- **Azure Entra** accepts credentials with an HTTPS issuer, an exact
  Kubernetes service account subject and the Azure token exchange audience.
  Parent exports can provide `clientId` or `appId` alongside
  `federatedIdentityCredentials` or `value`. Azure workload opt-in uses the
  label on the pod or its template. Azure role assignments are outside the
  supplied credential's scope.
- **Kubernetes** accepts workloads, service accounts, namespaces and RBAC.
  It models privileged containers and DaemonSets, hostPath and RBAC access to
  `nodes/proxy`. Baseline and restricted PodSecurity enforcement gates
  the modeled privileged and hostPath template paths. Existing Pod manifests
  remain analyzable because namespace policy changes do not evict pods.

Dashed edges represent conditional or runtime-dependent access. Effective
access depends on cluster exemptions, available token issuers, cloud
conditions, IAM boundaries, organization policies and other runtime controls.
PassRole remains a nontraversable finding because it depends on an additional
service API grant.

## Remediation

`remediation/cut-set.json` selects the fewest IAM or RBAC graph edges needed
to break all paths to impact 7 or higher within the requested hop limit. It
considers alternate routes and parallel edges. If a pair stays reachable after
all eligible edges are removed, the report marks the plan incomplete, lists
that pair, and finds a minimum cut for the remaining pairs. The exact search
can take longer on graphs with many interchangeable cuts.

The bundle includes a Terraform editing template, a legacy Kyverno
ClusterPolicy, Kyverno CEL-based ValidatingPolicy documents in audit mode,
and OPA Rego v1 admission checks. Review the selected edges and policy
templates against access requirements before applying changes. The policy
tests run OPA and Kyverno when both CLIs are available on `PATH`.

## Observed benchmark results

| Synthetic graph | Construction p50 / p95 (ms) | Pathfinding p50 / p95 (ms) |
| --- | ---: | ---: |
| 500 nodes | 2.303 / 2.643 | 5.575 / 14.107 |
| 2,000 nodes | 9.107 / 19.548 | 23.865 / 35.369 |

The two offline fixtures measured 100% combined precision and recall, with
zero false positives on the hardened fixture. The vulnerable fixture's
three-edge IAM/RBAC cut left zero high-risk pairs. Reproduction steps and
measurement scope are in [benchmarks/RESULTS.md](benchmarks/RESULTS.md).
