"""Pydantic v2 schemas for AWS IAM inventory, policies, and graph entities.

Everything in this module is a pure data model (no AWS SDK, no network). The
same JSON shapes are accepted from:

  * the built-in deterministic mock data (``--mock``),
  * an account dump file (``--account-file``), and
  * live ``iam.list_*`` results piped through ``engine.cli`` collectors.

Helpers here implement the *matching* primitives the analyzer relies on:
AWS-style ``*``/``?`` wildcard semantics for actions and ARNs, statement
evaluation (Deny overrides Allow), and principal matching for trust/resource
policies.
"""

from __future__ import annotations

import fnmatch
from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator

Effect = Literal["Allow", "Deny"]


def aws_match(pattern: str, value: str) -> bool:
    """AWS IAM wildcard match: ``*`` any run, ``?`` single char, case-insensitive.

    Mirrors the semantics AWS uses for actions and ARN resources.
    """
    if pattern == "*":
        return True
    return fnmatch.fnmatchcase(value.lower(), pattern.lower())


class PolicyStatement(BaseModel):
    """One IAM policy statement.

    ``principal`` and ``condition`` are only meaningful in trust/resource
    policies; identity statements carry ``action`` + ``resource``.
    """

    effect: Effect
    action: list[str] = Field(default_factory=list)
    resource: list[str] = Field(default_factory=list)
    principal: dict[str, Any] = Field(default_factory=dict)
    condition: dict[str, Any] = Field(default_factory=dict)
    sid: str | None = None

    @model_validator(mode="before")
    @classmethod
    def _normalize(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            raise ValueError(f"statement must be an object, got: {type(data).__name__}")  # noqa: TRY004
        out = dict(data)
        # Accept AWS-style capitalized keys in addition to our lowercase schema.
        for key in ("effect", "action", "resource", "sid"):
            cap = key.title() if key != "sid" else "Sid"
            if cap in out and key not in out:
                out[key] = out.pop(cap)
        out["effect"] = out.get("effect", "Allow")
        for key in ("action", "resource"):
            value = out.get(key)
            if value is not None and not isinstance(value, list):
                out[key] = [value]
        principal = out.pop("principal", out.pop("Principal", None))
        if principal is not None:
            if isinstance(principal, str):
                out["principal"] = {"AWS": [principal]}
            elif isinstance(principal, dict):
                out["principal"] = {
                    k: v if isinstance(v, list) else [v] for k, v in principal.items()
                }
        return out

    def allows(self, action: str, resource: str) -> bool:
        if self.effect != "Allow":
            return False
        return any(aws_match(a, action) for a in self.action) and any(
            aws_match(r, resource) for r in self.resource
        )

    def denies(self, action: str, resource: str) -> bool:
        if self.effect != "Deny":
            return False
        return any(aws_match(a, action) for a in self.action) and any(
            aws_match(r, resource) for r in self.resource
        )

    def principal_matches(self, actor_arn: str, account_id: str) -> bool:
        """Return True when this statement's Principal set admits ``actor_arn``.

        Supports AWS-style principals: ``*``, ``arn:aws:iam::<id>:root``,
        account id shorthand, and explicit user/role ARNs (with wildcards).
        Used for trust-policy and resource-policy evaluation.
        """
        principals = self.principal.get("AWS", [])
        if not principals:
            return False
        for entry in principals:
            if entry == "*":
                return True
            if entry.isdigit() and entry == account_id:
                return True
            if entry.startswith("arn:aws:iam::") and entry.endswith(":root"):
                if entry == f"arn:aws:iam::{account_id}:root":
                    return True
                continue
            if aws_match(entry, actor_arn):
                return True
        return False

    @property
    def is_allow_all(self) -> bool:
        """True when this statement allows ``*`` on ``*`` (admin-level grant)."""
        return self.effect == "Allow" and "*" in self.action and "*" in self.resource


class PolicyDocument(BaseModel):
    """A JSON IAM policy document (``Version`` + ``Statement`` list)."""

    version: str = "2012-10-17"
    statement: list[PolicyStatement] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def _normalize(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            raise ValueError(  # noqa: TRY004
                f"policy document must be an object, got: {type(data).__name__}"
            )
        statement = data.get("statement", data.get("Statement"))
        if isinstance(statement, dict):
            data = {**data, "statement": [statement]}
        elif statement is not None:
            data = {**data, "statement": statement}
        return data

    def allows(self, action: str, resource: str) -> bool:
        return any(stmt.allows(action, resource) for stmt in self.statement)

    def denies(self, action: str, resource: str) -> bool:
        return any(stmt.denies(action, resource) for stmt in self.statement)

    def principal_matches(self, actor_arn: str, account_id: str) -> bool:
        doc = self
        return any(
            stmt.principal_matches(actor_arn, account_id) for stmt in doc.statement
        )

    @property
    def is_admin(self) -> bool:
        return any(stmt.is_allow_all for stmt in self.statement)


class IamGroup(BaseModel):
    group_name: str
    arn: str
    policy_arns: list[str] = Field(default_factory=list)
    inline_policies: list[PolicyDocument] = Field(default_factory=list)


class IamPolicy(BaseModel):
    policy_name: str
    arn: str
    document: PolicyDocument


class IamIdentities(BaseModel):
    """Identity policies carried by both users and roles."""

    policy_arns: list[str] = Field(default_factory=list)
    inline_policies: list[PolicyDocument] = Field(default_factory=list)
    permissions_boundary: PolicyDocument | None = None


class IamUser(IamIdentities):
    username: str
    arn: str
    group_names: list[str] = Field(default_factory=list)


class IamRole(IamIdentities):
    role_name: str
    arn: str
    assume_role_policy: PolicyDocument | None = None

    @model_validator(mode="before")
    @classmethod
    def _pad_identity(cls, data: Any) -> Any:
        """Accept a plain role object lacking identity fields."""
        out = dict(data)
        for key in ("policy_arns", "inline_policies"):
            out.setdefault(key, [])
        out.setdefault("permissions_boundary", None)
        return out


class ResourcePolicy(BaseModel):
    """A resource-based policy (S3 bucket / KMS key / Secrets Manager secret)."""

    resource_type: Literal["s3", "kms", "secretsmanager"]
    arn: str
    policy: PolicyDocument


class AccountSnapshot(BaseModel):
    """The full offline IAM inventory handed to the analyzer."""

    account_id: str
    account_name: str = "corp"
    users: dict[str, IamUser] = Field(default_factory=dict)
    roles: dict[str, IamRole] = Field(default_factory=dict)
    groups: dict[str, IamGroup] = Field(default_factory=dict)
    policies: dict[str, IamPolicy] = Field(default_factory=dict)
    resource_policies: list[ResourcePolicy] = Field(default_factory=list)

    @property
    def principals_arns(self) -> list[str]:
        return list(self.users) + list(self.roles)

    def user_by_name(self, username: str) -> IamUser | None:
        for user in self.users.values():
            if user.username == username:
                return user
        return None

    def role_by_name(self, role_name: str) -> IamRole | None:
        for role in self.roles.values():
            if role.role_name == role_name:
                return role
        return None

    def effective_policies(self, principal: IamIdentities) -> list[PolicyDocument]:
        """Resolve identity policies (managed + inline + group + boundary)."""
        docs: list[PolicyDocument] = []
        for arn in principal.policy_arns:
            policy = self.policies.get(arn)
            if policy is not None:
                docs.append(policy.document)
        docs.extend(principal.inline_policies)
        if isinstance(principal, IamUser):
            for group_name in principal.group_names:
                group = self.groups.get(group_name)
                if group is None:
                    continue
                for arn in group.policy_arns:
                    policy = self.policies.get(arn)
                    if policy is not None:
                        docs.append(policy.document)
                docs.extend(group.inline_policies)
        return docs


class AttackNode(BaseModel):
    """A node in the attack-path graph."""

    id: str
    name: str
    kind: Literal["user", "role", "group", "policy", "resource", "admin"]
    arn: str | None = None
    is_admin: bool = False


class AttackEdge(BaseModel):
    """A directed edge in the attack-path graph."""

    source: str
    target: str
    relationship: str
    detail: str = ""


class AttackGraph(BaseModel):
    """Serializable graph of identity relationships and escalation edges."""

    nodes: list[AttackNode] = Field(default_factory=list)
    edges: list[AttackEdge] = Field(default_factory=list)


class EscalationFinding(BaseModel):
    """One confirmed escalation primitive, with the path that reaches it."""

    key: str
    vector: str
    mitre_id: str
    severity: Literal["critical", "high"]
    actor: str
    target: str
    description: str
    path: list[str] = Field(default_factory=list)


class AuditIssue(BaseModel):
    """A static statement-level warning for a single policy."""

    policy_name: str
    issue: str
    level: Literal["warning", "critical"]


class MitreRow(BaseModel):
    """One MITRE ATT&CK Cloud mapping row."""

    technique_id: str
    technique_name: str
    tactic: str
    vectors: list[str] = Field(default_factory=list)
