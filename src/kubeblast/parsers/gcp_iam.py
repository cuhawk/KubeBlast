import re

from ..models import CloudSecret, IAMRole, Inventory, Principal

from .oidc_parser import workload_account

WIF_SUBJECT = re.compile(
    r"principal://iam\.googleapis\.com/projects/[0-9]+/locations/global/"
    r"workloadIdentityPools/[a-z0-9.-]+\.svc\.id\.goog/subject/ns/([^/]+)/sa/([^/]+)"
)
WIF_NAMESPACE = re.compile(
    r"principalSet://iam\.googleapis\.com/projects/[0-9]+/locations/global/"
    r"workloadIdentityPools/[a-z0-9.-]+\.svc\.id\.goog/namespace/([^/]+)"
)

ADMIN_ROLES = {"roles/owner", "roles/editor", "roles/iam.securityAdmin", "roles/container.admin"}
IDENTITY_ROLES = {
    "roles/iam.serviceAccountTokenCreator", "roles/iam.serviceAccountUser",
    "roles/iam.workloadIdentityUser",
}


def parse_gcp(payload: dict, inventory: Inventory, evidence: str, accounts=()) -> None:
    policy = payload.get("iamPolicy", payload.get("policy", payload))
    resource = payload.get("resource") or payload.get("name")
    for binding in policy.get("bindings", []):
        role = binding.get("role")
        if not role:
            continue
        for member in binding.get("members", []):
            if not isinstance(member, str) or member.startswith("deleted:"):
                continue
            account = member.removeprefix("serviceAccount:")
            workload = next((node for node, namespace, name, target in accounts
                             if account.endswith(f".svc.id.goog[{namespace}/{name}]")
                             and resource and resource.endswith(f"/serviceAccounts/{target}")), None)
            subject = WIF_SUBJECT.fullmatch(member)
            namespace_group = WIF_NAMESPACE.fullmatch(member)
            if namespace_group:
                sources = [
                    node.id for node in inventory.nodes.values()
                    if node.kind == "service_account"
                    and node.label.split("/", 1)[0] == namespace_group[1]
                ]
            elif subject:
                sources = [workload_account(inventory, subject[1], subject[2])]
            elif workload:
                sources = [workload]
            elif member.startswith("serviceAccount:"):
                sources = [inventory.add(IAMRole(id=f"gcp:sa:{account}", label=account))]
            else:
                sources = [inventory.add(Principal(id=f"gcp:{member}", label=member, entry=True))]
            target_scope = resource or evidence
            conditional = bool(binding.get("condition"))
            finding = member in {"allUsers", "allAuthenticatedUsers"}
            rule = "gcp_binding"
            if role in IDENTITY_ROLES and resource and "/serviceAccounts/" in resource:
                target_account = resource.split("/serviceAccounts/", 1)[1]
                target = inventory.add(IAMRole(id=f"gcp:sa:{target_account}", label=target_account))
                rule = "gcp_workload_identity" if role.endswith("workloadIdentityUser") else "gcp_impersonation"
                conditional = True
                finding = finding or rule == "gcp_impersonation"
            elif role == "roles/secretmanager.secretAccessor":
                target = inventory.add(CloudSecret(
                    id=f"gcp:secret:{target_scope}", label=target_scope, impact=7
                ))
            else:
                impact = 10 if role in ADMIN_ROLES else 2
                target = inventory.add(IAMRole(
                    id=f"gcp:grant:{target_scope}:{role}", label=role, impact=impact
                ))
                finding = finding or role in ADMIN_ROLES
            for source in sources:
                federated = bool(subject or namespace_group)
                inventory.link(
                    source, target, "gcp_workload_identity" if federated else rule,
                    evidence, scope=target_scope, conditional=conditional or federated,
                    finding=finding or bool(namespace_group),
                )
