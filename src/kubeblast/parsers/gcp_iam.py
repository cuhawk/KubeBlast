from ..models import CloudSecret, IAMRole, Inventory, Principal

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
            if workload:
                source = workload
            elif member.startswith("serviceAccount:"):
                source = inventory.add(IAMRole(id=f"gcp:sa:{account}", label=account))
            else:
                source = inventory.add(Principal(id=f"gcp:{member}", label=member, entry=True))
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
            inventory.link(source, target, rule, evidence, scope=target_scope,
                           conditional=conditional, finding=finding)
