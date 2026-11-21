from urllib.parse import urlsplit

from ..models import IAMRole, Inventory
from .oidc_parser import sequence, workload_account


def parse_entra(payload: dict, inventory: Inventory, evidence: str, accounts=()) -> None:
    credentials = payload.get("federatedIdentityCredentials", payload.get("value", payload))
    for credential in sequence(credentials):
        properties = credential.get("properties", credential)
        client = (
            credential.get("clientId") or payload.get("clientId")
            or credential.get("appId") or payload.get("appId")
        )
        subject = properties.get("subject", "")
        issuer = urlsplit(properties.get("issuer", ""))
        if (
            issuer.scheme != "https" or not issuer.hostname or issuer.query or issuer.fragment
            or "api://AzureADTokenExchange" not in properties.get("audiences", [])
            or not subject.startswith("system:serviceaccount:")
        ):
            continue
        parts = subject.split(":")
        if len(parts) != 4:
            continue
        _, _, namespace, name = parts
        key = (namespace, name)
        annotation = accounts.get(key) if accounts else None
        if not client or not namespace or not name or (annotation and client != annotation):
            continue
        account = workload_account(inventory, namespace, name)
        target = inventory.add(IAMRole(id=f"azure:identity:{client}", label=client))
        inventory.link(account, target, "azure_entra_federated", evidence,
                       scope=issuer.geturl(), conditional=True)
