from ..models import GitHubOIDC, Inventory, K8sServiceAccount

ISSUER = "token.actions.githubusercontent.com"


def sequence(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def parse_trust(statements, role: str, inventory: Inventory, evidence: str) -> None:
    explicit_deny = any(statement.get("Effect") == "Deny" for statement in statements)
    for statement in statements:
        principal = statement.get("Principal", {})
        if statement.get("Effect") != "Allow" or not isinstance(principal, dict):
            continue
        providers = sequence(principal.get("Federated"))
        if not any(str(provider).endswith(f":oidc-provider/{ISSUER}") for provider in providers):
            continue
        actions = {str(action).lower() for action in sequence(statement.get("Action"))}
        if not actions.intersection({"sts:assumerolewithwebidentity", "sts:*", "*"}):
            continue
        conditions = statement.get("Condition", {})
        exact = conditions.get("StringEquals", {})
        like = conditions.get("StringLike", {})
        subjects = exact.get(f"{ISSUER}:sub", like.get(f"{ISSUER}:sub", "*"))
        audience = sequence(exact.get(f"{ISSUER}:aud"))
        for subject in sequence(subjects):
            subject = str(subject)
            broad = any(char in subject for char in "*?") or audience != ["sts.amazonaws.com"]
            source = inventory.add(GitHubOIDC(id=f"github:{subject}", label=subject, entry=True))
            inventory.link(
                source, role, "github_oidc", evidence, scope=subject,
                conditional=explicit_deny or bool(conditions), finding=broad,
            )


def workload_account(inventory: Inventory, namespace: str, name: str) -> str:
    return inventory.add(K8sServiceAccount(
        id=f"k8s:sa:{namespace}:{name}", label=f"{namespace}/{name}",
    ))
