from typing import Literal

from pydantic import BaseModel, Field


class Node(BaseModel):
    id: str
    label: str
    kind: str
    impact: int = Field(default=0, ge=0, le=10)
    entry: bool = False


class Principal(Node):
    kind: Literal["principal"] = "principal"


class IAMRole(Node):
    kind: Literal["iam_role"] = "iam_role"


class K8sServiceAccount(Node):
    kind: Literal["service_account"] = "service_account"


class K8sRole(Node):
    kind: Literal["rbac_role"] = "rbac_role"


class PodWorkload(Node):
    kind: Literal["workload"] = "workload"


class GitHubOIDC(Node):
    kind: Literal["github_oidc"] = "github_oidc"


class CloudSecret(Node):
    kind: Literal["cloud_secret"] = "cloud_secret"


class Edge(BaseModel):
    source: str
    target: str
    rule: str
    evidence: str
    scope: str = ""
    conditional: bool = False
    finding: bool = False
    traversable: bool = True


class Inventory(BaseModel):
    nodes: dict[str, Node] = Field(default_factory=dict)
    edges: list[Edge] = Field(default_factory=list)

    def add(self, node: Node) -> str:
        current = self.nodes.get(node.id)
        if current:
            node = node.model_copy(update={
                "impact": max(node.impact, current.impact),
                "entry": node.entry or current.entry,
            })
        self.nodes[node.id] = node
        return node.id

    def link(self, source: str, target: str, rule: str, evidence: str, **attributes) -> None:
        self.edges.append(Edge(
            source=source, target=target, rule=rule, evidence=evidence, **attributes
        ))
