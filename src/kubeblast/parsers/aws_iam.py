import json
import re
from fnmatch import fnmatchcase
from urllib.parse import unquote

from ..models import CloudSecret, IAMRole, Inventory, Principal
from .oidc_parser import parse_trust, sequence

DATA_REFERENCE = re.compile(r"^\$\{(data\.aws_iam_policy_document\.\w+)\.json\}$")
REFERENCE = re.compile(r"^\$\{(aws_iam_\w+\.\w+)\.(?:name|arn|id)\}$")


def matches(value: str, patterns) -> bool:
    return any(
        fnmatchcase(value, str(pattern).replace("[", "[[]"))
        for pattern in sequence(patterns)
    )


def document(value):
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        if value.startswith("${jsonencode(") and value.endswith(")}"):
            value = value[len("${jsonencode("):-2]
        try:
            return json.loads(unquote(value) if value.startswith("%7B") else value)
        except ValueError:
            return {}
    return {}


class AWSParser:
    def __init__(self, inventory: Inventory):
        self.inventory = inventory
        self.roles = {}
        self.policies = []
        self.terraform = {}
        self.memberships = {}
        self.data = {}

    def ingest(self, payload, source: str) -> None:
        for group in payload.get("GroupDetailList", []):
            name = group.get("GroupName") or group.get("Arn")
            if name:
                self.memberships[name] = group
        managed = {
            policy["Arn"]: next((
                version.get("Document", {}) for version in policy.get("PolicyVersionList", [])
                if version.get("IsDefaultVersion")
            ), {})
            for policy in payload.get("Policies", []) if "Arn" in policy
        }
        for key, inline in (("RoleDetailList", "RolePolicyList"), ("UserDetailList", "UserPolicyList")):
            for entry in payload.get(key, []):
                identity = entry.get("Arn")
                if not identity:
                    continue
                self.inventory.add(
                    IAMRole(id=identity, label=identity) if key == "RoleDetailList"
                    else Principal(id=identity, label=identity, entry=True)
                )
                if key == "RoleDetailList":
                    self.roles[identity] = (document(entry.get("AssumeRolePolicyDocument")), source)
                group_entries = [
                    self.memberships[name] for name in entry.get("GroupList", [])
                    if name in self.memberships
                ]
                policies = list(entry.get(inline, []))
                attachments = list(entry.get("AttachedManagedPolicies", []))
                for group in group_entries:
                    policies.extend(group.get("GroupPolicyList", []))
                    attachments.extend(group.get("AttachedManagedPolicies", []))
                for policy in policies:
                    self.policies.append((identity, document(policy.get("PolicyDocument")), source))
                for attachment in attachments:
                    arn = attachment.get("PolicyArn")
                    if arn in managed:
                        self.policies.append((identity, document(managed[arn]), source))
                    elif arn and arn.endswith(":policy/AdministratorAccess"):
                        self.policies.append((identity, {"Statement": {
                            "Effect": "Allow", "Action": "*", "Resource": "*"
                        }}, source))
        if "Statement" in payload:
            identity = payload.get("PrincipalArn", f"aws:policy:{source}")
            self.inventory.add(Principal(id=identity, label=identity, entry=True))
            self.policies.append((identity, payload, source))

    def ingest_hcl(self, payload, source: str) -> None:
        for block in payload.get("data", []):
            for name, config in block.get("aws_iam_policy_document", {}).items():
                statements = []
                for declaration in config.get("statement", []):
                    statement = {"Effect": declaration.get("effect", "Allow")}
                    for key, field in {
                        "actions": "Action", "resources": "Resource",
                        "not_actions": "NotAction", "not_resources": "NotResource",
                    }.items():
                        if key in declaration:
                            statement[field] = declaration[key]
                    for principal in declaration.get("principals", []):
                        statement.setdefault("Principal", {})[principal["type"]] = principal["identifiers"]
                    for condition in declaration.get("condition", []):
                        statement.setdefault("Condition", {}).setdefault(condition["test"], {})[
                            condition["variable"]
                        ] = condition["values"]
                    statements.append(statement)
                self.data[f"data.aws_iam_policy_document.{name}"] = {"Statement": statements}
        for block in payload.get("resource", []):
            for resource_type, resources in block.items():
                for name, config in resources.items():
                    self.terraform[f"{resource_type}.{name}"] = (resource_type, config, source)

    def hcl_document(self, value):
        reference = DATA_REFERENCE.fullmatch(value) if isinstance(value, str) else None
        return self.data.get(reference[1], {}) if reference else document(value)

    def resolve_hcl(self) -> None:
        identities = {}
        for address, (kind, config, source) in self.terraform.items():
            if kind not in {"aws_iam_role", "aws_iam_user"}:
                continue
            name = config.get("name", address)
            if not isinstance(name, str):
                name = address
            identity = config.get("arn") or f"aws:terraform:{kind}:{name}"
            node = IAMRole(id=identity, label=name) if kind == "aws_iam_role" else Principal(
                id=identity, label=name, entry=True
            )
            self.inventory.add(node)
            identities[address] = identities[name] = identity
            if kind == "aws_iam_role":
                self.roles[identity] = (self.hcl_document(config.get("assume_role_policy")), source)
                for policy in config.get("inline_policy", []):
                    self.policies.append((identity, self.hcl_document(policy.get("policy")), source))

        for kind, config, source in self.terraform.values():
            if kind not in {
                "aws_iam_role_policy", "aws_iam_user_policy",
                "aws_iam_role_policy_attachment", "aws_iam_user_policy_attachment",
            }:
                continue
            reference = config.get("role") or config.get("user") or ""
            if not isinstance(reference, str):
                continue
            match = REFERENCE.fullmatch(reference)
            identity = identities.get(match[1] if match else reference)
            if not identity:
                continue
            policy = config.get("policy")
            if kind.endswith("_attachment"):
                arn = config.get("policy_arn", "")
                match = REFERENCE.fullmatch(arn) if isinstance(arn, str) else None
                if match and match[1] in self.terraform:
                    policy = self.terraform[match[1]][1].get("policy")
                elif isinstance(arn, str) and arn.endswith(":policy/AdministratorAccess"):
                    policy = {"Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}}
            self.policies.append((identity, self.hcl_document(policy), source))

    def finish(self, federated_accounts=()) -> None:
        self.resolve_hcl()
        for role, (policy, source) in self.roles.items():
            statements = sequence(policy.get("Statement"))
            parse_trust(statements, role, self.inventory, source)
            for account, target, subject in federated_accounts:
                if target != role:
                    continue
                for statement in statements:
                    principal = statement.get("Principal", {})
                    if statement.get("Effect") != "Allow" or not isinstance(principal, dict):
                        continue
                    providers = [
                        provider.split("oidc-provider/", 1)[1]
                        for provider in sequence(principal.get("Federated"))
                        if isinstance(provider, str) and "oidc-provider/" in provider
                        and "oidc.eks." in provider
                    ]
                    if not providers or not matches(
                        "sts:assumerolewithwebidentity",
                        [str(action).lower() for action in sequence(statement.get("Action"))],
                    ):
                        continue
                    conditions = statement.get("Condition", {})
                    for provider in providers:
                        exact = conditions.get("StringEquals", {}).get(f"{provider}:sub")
                        like = conditions.get("StringLike", {}).get(f"{provider}:sub", "*")
                        allowed = subject in sequence(exact) if exact is not None else matches(subject, like)
                        if not allowed:
                            continue
                        self.inventory.link(
                            account, role, "aws_irsa", source, scope=subject,
                            conditional=True, finding=exact is None,
                        )
                        break

        by_identity = {}
        for identity, policy, source in self.policies:
            for statement in sequence(policy.get("Statement")):
                by_identity.setdefault(identity, []).append((statement, source))
        for identity, statements in by_identity.items():
            denies = [statement for statement, _ in statements if statement.get("Effect") == "Deny"]
            for statement, source in statements:
                if statement.get("Effect") != "Allow":
                    continue
                actions = [str(action).lower() for action in sequence(statement.get("Action"))]
                resources = statement.get("Resource")
                if not resources:
                    continue
                conditional = bool(statement.get("Condition")) or bool(denies)
                if "*" in actions and "*" in sequence(resources):
                    admin = self.inventory.add(Principal(id="aws:admin-capability", label="AWS administrative capability", impact=10))
                    self.inventory.link(identity, admin, "aws_admin", source, conditional=conditional, finding=True, scope="*")
                role_patterns = [
                    self.terraform_identity(resource) if isinstance(resource, str) else resource
                    for resource in sequence(resources)
                ]
                for role, (trust, _) in self.roles.items():
                    if not matches(role, role_patterns):
                        continue
                    if matches("sts:assumerole", actions) and self.trusts(identity, trust) and not self.denied(
                        denies, "sts:assumerole", role
                    ):
                        self.inventory.link(identity, role, "aws_assume_role", source, scope=role, conditional=True, finding=True)
                    if matches("iam:passrole", actions) and not self.denied(denies, "iam:passrole", role):
                        same_account = not (
                            identity.startswith("arn:") and role.startswith("arn:")
                            and identity.split(":")[4] != role.split(":")[4]
                        )
                        if same_account:
                            self.inventory.link(
                                identity, role, "aws_pass_role", source, scope=role,
                                conditional=True, finding=True, traversable=False,
                            )
                for resource in sequence(resources):
                    if not isinstance(resource, str):
                        continue
                    if matches("secretsmanager:getsecretvalue", actions) and (
                        ":secretsmanager:" in resource or resource == "*"
                    ) and not self.denied(denies, "secretsmanager:getsecretvalue", resource):
                        secret = self.inventory.add(CloudSecret(
                            id=f"aws:secret:{resource}", label=resource, impact=7
                        ))
                        self.inventory.link(identity, secret, "aws_secret_read", source, scope=resource, conditional=conditional, finding=resource == "*")

    def terraform_identity(self, value):
        match = REFERENCE.fullmatch(value)
        if match and match[1] in self.terraform:
            kind, config, _ = self.terraform[match[1]]
            return config.get("arn") or f"aws:terraform:{kind}:{config.get('name', match[1])}"
        return value

    @staticmethod
    def denied(statements, action, resource):
        for statement in statements:
            if statement.get("Condition"):
                continue
            actions = [str(value).lower() for value in sequence(statement.get("Action"))]
            resources = statement.get("Resource")
            if matches(action, actions) and (
                "*" in sequence(resources) or (resource != "*" and matches(resource, resources))
            ):
                return True
        return False

    def trusts(self, identity, policy) -> bool:
        for statement in sequence(policy.get("Statement")):
            if statement.get("Effect") != "Allow":
                continue
            actions = [str(action).lower() for action in sequence(statement.get("Action"))]
            if not matches("sts:assumerole", actions):
                continue
            principal = statement.get("Principal")
            if principal == "*":
                return True
            if isinstance(principal, dict):
                for allowed in sequence(principal.get("AWS")):
                    if isinstance(allowed, str):
                        allowed = self.terraform_identity(allowed)
                    if allowed in {"*", identity}:
                        return True
                    if isinstance(allowed, str) and allowed.endswith(":root"):
                        if identity.startswith(allowed.removesuffix("root")):
                            return True
        return False
