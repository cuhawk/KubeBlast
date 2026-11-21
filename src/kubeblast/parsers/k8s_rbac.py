from ..models import Inventory, K8sRole, PodWorkload, Principal

from .oidc_parser import workload_account

TEMPLATE_KINDS = {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job"}


def permits(rule, verb, resource, group=""):
    resources = rule.get("resources", [])
    subresource = resource.split("/", 1)
    return (
        bool({verb, "*"}.intersection(rule.get("verbs", [])))
        and bool({group, "*"}.intersection(rule.get("apiGroups", [""])))
        and (
            bool({resource, "*"}.intersection(resources))
            or (len(subresource) == 2 and f"*/{subresource[1]}" in resources)
        )
    )


class KubernetesParser:
    def __init__(self, inventory: Inventory):
        self.inventory = inventory
        self.documents = []
        self.aws_accounts = []
        self.gcp_accounts = []
        self.azure_accounts = {}
        self.namespace_profiles = {}
        self.admitted_exposures = {}
        self.identity_mounts = {}
        self.account_specs = {}
        self.workloads = {}

    def ingest(self, document, source: str) -> None:
        if document.get("kind") in {"List", "RoleList", "ClusterRoleList"}:
            for item in document.get("items", []):
                self.ingest(item, source)
        else:
            self.documents.append((document, source))

    def account(self, namespace, name):
        return workload_account(self.inventory, namespace, name)

    def subject(self, subject, namespace):
        name = subject.get("name")
        if not name:
            return None
        if subject.get("kind") == "ServiceAccount":
            return self.account(subject.get("namespace", namespace), name)
        kind = subject.get("kind")
        if kind in {"User", "Group"}:
            if kind == "User" and name.startswith("system:serviceaccount:"):
                _, _, sa_namespace, sa_name = name.split(":", 3)
                return self.account(sa_namespace, sa_name)
            return self.inventory.add(Principal(
                id=f"k8s:{kind.lower()}:{name}", label=name, entry=True
            ))
        return None

    def finish(self) -> None:
        roles = {("ClusterRole", "*", "cluster-admin"): [{
            "apiGroups": ["*"], "verbs": ["*"], "resources": ["*"]
        }]}
        role_sources = {}
        bindings = []
        workloads = []
        for document, source in self.documents:
            kind = document.get("kind")
            metadata = document.get("metadata", {})
            name = metadata.get("name")
            if not name:
                continue
            namespace = metadata.get("namespace", "default")
            if kind == "Namespace":
                labels = metadata.get("labels", {})
                self.namespace_profiles[name] = labels.get("pod-security.kubernetes.io/enforce")
            elif kind == "ServiceAccount":
                account = self.account(namespace, name)
                self.account_specs[account] = document
                annotations = metadata.get("annotations", {})
                if client := annotations.get("azure.workload.identity/client-id"):
                    self.azure_accounts[namespace, name] = client
                if role := annotations.get("eks.amazonaws.com/role-arn"):
                    self.aws_accounts.append((account, role, f"system:serviceaccount:{namespace}:{name}"))
                if annotations.get("iam.gke.io/gcp-service-account"):
                    self.gcp_accounts.append((account, namespace, name, annotations["iam.gke.io/gcp-service-account"]))
            elif kind in {"Role", "ClusterRole"}:
                scope = "*" if kind == "ClusterRole" else namespace
                roles[kind, scope, name] = document.get("rules", [])
                role_sources[kind, scope, name] = source
                self.role(kind, scope, name)
            elif kind in {"RoleBinding", "ClusterRoleBinding"}:
                bindings.append((document, source, namespace))
            elif kind == "Pod" or kind in TEMPLATE_KINDS or kind == "CronJob":
                workloads.append((document, source, namespace, name))

        for document, source, namespace, name in workloads:
            self.workload(document, source, namespace, name)

        for document, _, namespace in bindings:
            for subject in document.get("subjects", []):
                if (document["kind"] != "ClusterRoleBinding"
                        or subject.get("kind") != "ServiceAccount" or subject.get("namespace")):
                    self.subject(subject, namespace)

        effective_roles = set()
        for document, source, namespace in bindings:
            ref = document.get("roleRef", {})
            name = ref.get("name")
            kind = ref.get("kind")
            cluster_wide = document["kind"] == "ClusterRoleBinding"
            role_scope = "*" if kind == "ClusterRole" else namespace
            key = (kind, role_scope, name)
            if key not in roles or (cluster_wide and kind != "ClusterRole"):
                continue
            scope = "*" if cluster_wide else namespace
            role = self.role(kind, scope, name)
            for subject in document.get("subjects", []):
                if cluster_wide and subject.get("kind") == "ServiceAccount" and not subject.get("namespace"):
                    continue
                if principal := self.subject(subject, namespace):
                    self.inventory.link(principal, role, "k8s_binding", source, scope=scope,
                                        finding=cluster_wide and name == "cluster-admin")
            if role not in effective_roles:
                effective_roles.add(role)
                for rule in roles[key]:
                    self.permissions(role, rule, scope, roles, role_sources.get(key, source))

    def role(self, kind, scope, name):
        return self.inventory.add(K8sRole(
            id=f"k8s:role:{kind}:{scope}:{name}", label=f"{name} ({scope})",
            impact=10 if name == "cluster-admin" and scope == "*" and kind == "ClusterRole" else 0,
        ))

    def workload(self, document, source, namespace, name):
        kind = document["kind"]
        spec = document.get("spec", {})
        pod_metadata = document.get("metadata", {})
        if kind == "CronJob":
            spec = spec.get("jobTemplate", {}).get("spec", {})
        if kind != "Pod":
            template = spec.get("template", {})
            pod_metadata = template.get("metadata", {})
            spec = template.get("spec", {})
        node = self.inventory.add(PodWorkload(
            id=f"k8s:workload:{namespace}:{kind}:{name}", label=f"{kind} {namespace}/{name}",
            entry=True,
        ))
        self.workloads[node] = (namespace, name, kind)
        account = self.account(namespace, spec.get("serviceAccountName", "default"))
        self.identity_mounts[node] = (
            account, source, namespace,
            pod_metadata.get("labels", {}).get("azure.workload.identity/use") == "true",
        )
        account_spec = self.account_specs.get(account, {})
        projected_token = any(
            "serviceAccountToken" in projection
            for volume in spec.get("volumes", [])
            for projection in volume.get("projected", {}).get("sources", [])
        )
        if projected_token or spec.get(
            "automountServiceAccountToken", account_spec.get("automountServiceAccountToken", True)
        ):
            self.inventory.link(node, account, "k8s_token_mount", source, scope=namespace, finding=True)
        containers = [
            container for field in ("containers", "initContainers", "ephemeralContainers")
            for container in spec.get(field, [])
        ]
        exposures = {
            "k8s_hostpath": any("hostPath" in volume for volume in spec.get("volumes", [])),
            "k8s_privileged": any(c.get("securityContext", {}).get("privileged") is True for c in containers),
        }
        profile = self.namespace_profiles.get(namespace)
        blocked = profile in {"baseline", "restricted"}
        if any(exposures.values()):
            self.admitted_exposures[node] = not blocked
            if blocked:
                policy = self.inventory.add(Principal(
                    id=f"k8s:podsecurity:{namespace}:{profile}", label=f"{namespace} {profile}",
                ))
                if kind != "Pod":
                    self.inventory.nodes[node] = self.inventory.nodes[node].model_copy(update={"entry": False})
                self.inventory.link(policy, node, "k8s_podsecurity_enforced", source,
                                    scope=namespace, traversable=False)
        for rule, detected in exposures.items():
            if not detected:
                continue
            target = self.inventory.add(Principal(
                id=f"k8s:host:{namespace}:{kind}:{name}", label=f"Host of {namespace}/{name}", impact=8
            ))
            # Admission does not evict pods that are already running.
            traversable = kind == "Pod" or not blocked
            exposure = "k8s_privileged_daemonset" if kind == "DaemonSet" and rule == "k8s_privileged" else rule
            self.inventory.link(node, target, exposure, source, scope=namespace,
                                finding=traversable, traversable=traversable, conditional=True)

    def finish_identity_mounts(self):
        trusts = {}
        for edge in self.inventory.edges:
            if edge.rule in {"aws_irsa", "aws_eks_pod_identity", "gcp_workload_identity", "azure_entra_federated"}:
                trusts.setdefault(edge.source, []).append(edge)
        for node, (account, source, namespace, azure_enabled) in self.identity_mounts.items():
            edges = trusts.get(account, [])
            if any(edge.rule != "azure_entra_federated" or azure_enabled for edge in edges):
                self.inventory.link(node, account, "k8s_workload_identity", source,
                                    scope=namespace, conditional=True)

    def permissions(self, role, rule, scope, roles, source):
        names = rule.get("resourceNames", [])
        if scope == "*" and any(
            permits(rule, verb, "nodes/proxy") for verb in ("get", "create")
        ):
            for node_name in names or ["*"]:
                target = self.inventory.add(Principal(
                    id=f"k8s:node-proxy:{node_name}", label=f"Node proxy ({node_name})", impact=8,
                ))
                self.inventory.link(role, target, "k8s_node_proxy", source,
                                    scope=node_name, conditional=True, finding=True)
        for workload, (namespace, name, kind) in self.workloads.items():
            if scope not in {"*", namespace}:
                continue
            if self.admitted_exposures.get(workload) and (
                (not names and permits(rule, "create", "pods" if kind == "Pod" else "daemonsets",
                                       "" if kind == "Pod" else "apps") and kind in {"Pod", "DaemonSet"})
                or (kind == "DaemonSet" and (not names or name in names) and any(
                    permits(rule, verb, "daemonsets", "apps") for verb in ("update", "patch")
                ))
            ):
                self.inventory.link(role, workload, "k8s_workload_write", source,
                                    scope=namespace, conditional=True, finding=True)
            if kind == "Pod" and (not names or name in names) and any(
                permits(rule, verb, "pods/exec") for verb in ("create", "get")
            ):
                self.inventory.link(role, workload, "k8s_exec", source, scope=namespace,
                                    conditional=True, finding=True)

        group = "rbac.authorization.k8s.io"
        for verb in ("bind", "escalate"):
            for kind, namespace, name in roles:
                resource = "clusterroles" if kind == "ClusterRole" else "roles"
                if names and name not in names:
                    continue
                if kind == "Role" and scope not in {"*", namespace}:
                    continue
                if kind == "ClusterRole" and scope != "*":
                    continue
                if permits(rule, verb, resource, group):
                    target = self.role(kind, namespace, name)
                    self.inventory.link(role, target, f"k8s_{verb}", source, scope=scope,
                                        conditional=True, finding=True)

        if permits(rule, "impersonate", "serviceaccounts"):
            for account in list(self.inventory.nodes.values()):
                if account.kind != "service_account":
                    continue
                namespace, name = account.label.split("/", 1)
                if scope in {"*", namespace} and (not names or name in names):
                    self.inventory.link(role, account.id, "k8s_impersonate", source,
                                        scope=namespace, conditional=True, finding=True)
        if scope == "*" and any(permits(rule, "impersonate", resource) for resource in ("users", "groups")):
            for identity in list(self.inventory.nodes.values()):
                kind = identity.id.split(":")[1] if identity.id.startswith("k8s:") else ""
                if kind in {"user", "group"} and permits(rule, "impersonate", f"{kind}s"):
                    if not names or identity.label in names:
                        self.inventory.link(role, identity.id, "k8s_impersonate", source,
                                            scope=scope, conditional=True, finding=True)
