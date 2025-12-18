"""IAM permission evaluation: escalate, chain, and exfil detection.

Walks an :class:`AccountSnapshot` and finds the classic IAM privilege-
escalation primitives (Rhino Security / Spencer Gietzen), PassRole chains to
compute services, cross-role trust-hop paths, and public data exfiltration.

Everything is offline-deterministic: no AWS SDK, no network.
"""

from __future__ import annotations

import itertools
from collections import deque
from collections.abc import Iterable

from engine.config import (
    AccountSnapshot,
    AttackEdge,
    AttackGraph,
    AttackNode,
    AuditIssue,
    EscalationFinding,
    IamGroup,
    IamIdentities,
    IamPolicy,
    IamRole,
    IamUser,
    PolicyDocument,
    PolicyStatement,
    aws_match,
)

ADMIN_ACTION = "*"
ADMIN_RESOURCE = "*"

# PassRole escalation pairs: (compute action, [required actions, ...]).
PASSROLE_COMPUTE: dict[str, list[str]] = {
    "lambda:CreateFunction": ["lambda:CreateFunction", "lambda:InvokeFunction"],
    "ec2:RunInstances": ["ec2:RunInstances"],
    "cloudformation:CreateStack": ["cloudformation:CreateStack"],
    "ecs:RegisterTaskDefinition": ["ecs:RegisterTaskDefinition", "ecs:RunTask"],
    "glue:CreateDevEndpoint": ["glue:CreateDevEndpoint", "glue:GetDevEndpoint"],
    "sagemaker:CreateNotebookInstance": [
        "sagemaker:CreateNotebookInstance",
        "sagemaker:CreatePresignedNotebookInstanceUrl",
    ],
    "datapipeline:CreatePipeline": [
        "datapipeline:CreatePipeline",
        "datapipeline:ActivatePipeline",
    ],
    "codebuild:CreateProject": ["codebuild:CreateProject", "codebuild:StartBuild"],
    "batch:RegisterJobDefinition": ["batch:RegisterJobDefinition", "batch:SubmitJob"],
    "datasync:CreateTask": ["datasync:CreateTask", "datasync:UpdateTask"],
    "wellarchitected:CreateWorkload": [
        "wellarchitected:CreateWorkload",
        "wellarchitected:UpdateWorkload",
    ],
}

MITRE_ELEVATION = "T1548.004"
MITRE_PASSROLE = "T1548.004"
MITRE_ASSUMEROLE = "T1078.004"
MITRE_S3_EXFIL = "T1530"
MITRE_SECRET_EXFIL = "T1552.005"
MITRE_KMS_EXFIL = "T1552.005"


class PermissionEvaluator:
    """Evaluate an actor's effective permissions from an account snapshot."""

    def __init__(self, account: AccountSnapshot) -> None:
        self.account = account

    def allow(self, actor: str, action: str, resource: str = "*") -> bool:
        """True when ``actor`` may call ``action`` on ``resource``.

        AWS semantics: any explicit Deny that matches wins; otherwise any
        matching Allow grants. When a permissions boundary is present, the
        boundary must ALSO allow the action (identity allow AND boundary
        allow), and a Deny inside the boundary still blocks.
        """
        identity = self.identity(actor)
        if identity is None:
            return False
        docs = self.account.effective_policies(identity)
        boundary = identity.permissions_boundary

        def _matches(stmt: PolicyStatement) -> bool:
            return any(aws_match(a, action) for a in stmt.action) and any(
                aws_match(r, resource) for r in stmt.resource
            )

        all_stmts = [stmt for doc in docs for stmt in doc.statement]
        if boundary is not None:
            all_stmts.extend(boundary.statement)
        if any(stmt.effect == "Deny" and _matches(stmt) for stmt in all_stmts):
            return False
        allowed = any(
            stmt.effect == "Allow" and _matches(stmt)
            for doc in docs
            for stmt in doc.statement
        )
        if not allowed:
            return False
        if boundary is not None:
            return any(
                stmt.effect == "Allow" and _matches(stmt) for stmt in boundary.statement
            )
        return True

    def identity(self, actor: str) -> IamIdentities | None:
        return self.account.users.get(actor) or self.account.roles.get(actor)

    def sts_allow(self, actor: str, role_arn: str) -> bool:
        return self.allow(actor, "sts:AssumeRole", role_arn)

    def assume_policy_match(self, actor: str, role: IamRole) -> bool:
        """Does the role's trust policy admit this actor (incl. account root)?"""
        policy = role.assume_role_policy
        if policy is None:
            return False
        return any(
            stmt.principal_matches(actor, self.account.account_id)
            for stmt in policy.statement
        )

    def can_assume(self, actor: str, role: IamRole) -> bool:
        """AWS requires BOTH the trust policy on the role AND an identity-pol
        Allow for sts:AssumeRole on the role ARN."""
        return self.sts_allow(actor, role.arn) and self.assume_policy_match(actor, role)

    def is_privileged(self, role: IamRole) -> bool:
        docs = self.account.effective_policies(role)
        boundary = role.permissions_boundary
        if boundary is not None:
            docs = [*docs, boundary]
        return any(doc.is_admin for doc in docs)


class IamAnalyzer:
    """Finds escalation pathways through an account snapshot."""

    def __init__(self, account: AccountSnapshot) -> None:
        self.account = account
        self.perm = PermissionEvaluator(account)

    # ------------------------------------------------------------- plumbing

    def _findings(self) -> list[EscalationFinding]:
        """Core scan; wrapped by analyze() which adds graph metadata."""
        findings: list[EscalationFinding] = []
        for actor in self.account.users:
            if self._is_root_admin(actor):
                continue
            findings.extend(self._escale_actor(actor))
            findings.extend(self._passrole_actor(actor))
            findings.extend(self._assume_actor(actor))
        findings.extend(self._public_exposure())
        return findings

    def analyze(self) -> tuple[list[EscalationFinding], AttackGraph]:
        findings = self._findings()
        graph = self._build_graph(findings)
        return findings, graph

    # --------------------------------------------------- actor escalation

    def _escale_actor(self, actor: str) -> list[EscalationFinding]:
        user = self.account.users[actor]
        out: list[EscalationFinding] = []
        admin_policies = self._admin_policies()

        # -- attach / put admin policy to self (requires an admin policy doc)
        for action in ("iam:AttachUserPolicy", "iam:PutUserPolicy"):
            if admin_policies and (
                self.perm.allow(actor, action, actor) or self.perm.allow(actor, action)
            ):
                out.append(
                    EscalationFinding(
                        key=f"{actor}|{action}->self",
                        vector=f"{action} -> Admin on self",
                        mitre_id=MITRE_ELEVATION,
                        severity="critical",
                        actor=actor,
                        target=actor,
                        description=f"{action} on own principal with an admin-managed policy present",
                        path=[actor, "ADMIN"],
                    )
                )

        # -- escalation via groups (attach admin to a group the actor belongs to)
        for group in self._actor_groups(actor):
            is_admin_group = "admin" in group.group_name.lower() or any(
                p.document.is_admin for p in self._policies_for_group(group)
            )
            if is_admin_group and (
                self.perm.allow(actor, "iam:AttachGroupPolicy", group.arn)
                or self.perm.allow(actor, "iam:AttachGroupPolicy")
            ):
                out.append(
                    EscalationFinding(
                        key=f"{actor}|AttachGroupPolicy->{group.arn}",
                        vector="iam:AttachGroupPolicy -> Admin group",
                        mitre_id=MITRE_ELEVATION,
                        severity="critical",
                        actor=actor,
                        target=group.arn,
                        description=f"Attach an admin policy to group {group.group_name}",
                        path=[actor, group.arn, "ADMIN"],
                    )
                )

        # -- CreatePolicy + Attach/self (create own admin policy)
        if self.perm.allow(actor, "iam:CreatePolicy") and (
            self.perm.allow(actor, "iam:AttachUserPolicy", actor)
            or self.perm.allow(actor, "iam:PutUserPolicy", actor)
        ):
            out.append(
                EscalationFinding(
                    key=f"{actor}|CreatePolicy+attach",
                    vector="iam:CreatePolicy + iam:AttachUserPolicy",
                    mitre_id=MITRE_ELEVATION,
                    severity="critical",
                    actor=actor,
                    target=actor,
                    description="Create a fresh admin policy and attach it to self",
                    path=[actor, "ADMIN"],
                )
            )

        # -- policy version manipulation (on a policy attached to self)
        for policy in admin_or_all_policies(self.account):
            if self.perm.allow(
                actor, "iam:CreatePolicyVersion", policy.arn
            ) and self.perm.allow(actor, "iam:SetDefaultPolicyVersion", policy.arn):
                attached = policy.arn in user.policy_arns or any(
                    policy.arn == p for p in self._actor_group_policy_arns(user)
                )
                if attached:
                    out.append(
                        EscalationFinding(
                            key=f"{actor}|CreatePolicyVersion->{policy.arn}",
                            vector="iam:CreatePolicyVersion + iam:SetDefaultPolicyVersion",
                            mitre_id=MITRE_ELEVATION,
                            severity="critical",
                            actor=actor,
                            target=policy.arn,
                            description="Overwrite a policy attached to self with an admin version",
                            path=[actor, policy.arn, "ADMIN"],
                        )
                    )

        # -- AddUserToGroup for an admin group
        for group in self.account.groups.values():
            is_admin_group = "admin" in group.group_name.lower() or any(
                arn in self.account.policies
                and self.account.policies[arn].document.is_admin
                for arn in group.policy_arns
            )
            if is_admin_group and (
                self.perm.allow(actor, "iam:AddUserToGroup", group.arn)
                or self.perm.allow(actor, "iam:AddUserToGroup")
            ):
                out.append(
                    EscalationFinding(
                        key=f"{actor}|AddUserToGroup->{group.arn}",
                        vector="iam:AddUserToGroup -> Admin group",
                        mitre_id=MITRE_ELEVATION,
                        severity="critical",
                        actor=actor,
                        target=group.arn,
                        description=f"Add self to admin group {group.group_name}",
                        path=[actor, group.arn, "ADMIN"],
                    )
                )

        # -- credential misdirection against admin users
        for target_user in self.account.users.values():
            if not self._is_root_admin(target_user.arn):
                continue
            if self.perm.allow(
                actor, "iam:CreateAccessKey", target_user.arn
            ) or self.perm.allow(actor, "iam:CreateAccessKey"):
                out.append(
                    EscalationFinding(
                        key=f"{actor}|CreateAccessKey->{target_user.arn}",
                        vector="iam:CreateAccessKey -> Admin credentials",
                        mitre_id=MITRE_ASSUMEROLE,
                        severity="critical",
                        actor=actor,
                        target=target_user.arn,
                        description=f"Mint new access keys for admin user {target_user.username}",
                        path=[actor, target_user.arn, "ADMIN"],
                    )
                )
            if self.perm.allow(
                actor, "iam:UpdateLoginProfile", target_user.arn
            ) or self.perm.allow(actor, "iam:UpdateLoginProfile"):
                out.append(
                    EscalationFinding(
                        key=f"{actor}|UpdateLoginProfile->{target_user.arn}",
                        vector="iam:UpdateLoginProfile -> Admin console password",
                        mitre_id=MITRE_ASSUMEROLE,
                        severity="critical",
                        actor=actor,
                        target=target_user.arn,
                        description=f"Reset admin user {target_user.username} console login",
                        path=[actor, target_user.arn, "ADMIN"],
                    )
                )

        # -- UpdateAssumeRolePolicy on a privileged role + assume it
        for role in self.account.roles.values():
            if not self.perm.is_privileged(role):
                continue
            can_update = self.perm.allow(
                actor, "iam:UpdateAssumeRolePolicy", role.arn
            ) or self.perm.allow(actor, "iam:UpdateAssumeRolePolicy")
            if not can_update:
                continue
            if self.perm.sts_allow(actor, role.arn):
                out.append(
                    EscalationFinding(
                        key=f"{actor}|UpdateAssumeRolePolicy->{role.arn}",
                        vector="iam:UpdateAssumeRolePolicy -> assume privileged role",
                        mitre_id=MITRE_ELEVATION,
                        severity="critical",
                        actor=actor,
                        target=role.arn,
                        description=f"Rewrite trust policy of {role.role_name} to admit self, then assume it",
                        path=[actor, role.arn, "ADMIN"],
                    )
                )

        # -- attach admin policy to an assumable role
        for role in self.account.roles.values():
            if not self.perm.can_assume(actor, role):
                continue
            if admin_policies and (
                self.perm.allow(actor, "iam:AttachRolePolicy", role.arn)
                or self.perm.allow(actor, "iam:AttachRolePolicy")
            ):
                out.append(
                    EscalationFinding(
                        key=f"{actor}|AttachRolePolicy->{role.arn}",
                        vector="iam:AttachRolePolicy -> assumable admin role",
                        mitre_id=MITRE_ELEVATION,
                        severity="critical",
                        actor=actor,
                        target=role.arn,
                        description=f"Attach admin policy to assumable role {role.role_name}",
                        path=[actor, role.arn, "ADMIN"],
                    )
                )
        return out

    # ------------------------------------------------------- PassRole chains

    def _passrole_actor(self, actor: str) -> list[EscalationFinding]:
        out: list[EscalationFinding] = []
        for role in self.account.roles.values():
            if not self.perm.is_privileged(role):
                continue
            for service_action, required in PASSROLE_COMPUTE.items():
                if not self.perm.allow(
                    actor, "iam:PassRole", role.arn
                ) and not self.perm.allow(actor, "iam:PassRole"):
                    continue
                have_actions = {a for a in required if self.perm.allow(actor, a)}
                if have_actions and all(self.perm.allow(actor, a) for a in required):
                    out.append(
                        EscalationFinding(
                            key=f"{actor}|PassRole:{service_action}->{role.arn}",
                            vector=f"iam:PassRole + {service_action} -> {role.role_name}",
                            mitre_id=MITRE_PASSROLE,
                            severity="critical",
                            actor=actor,
                            target=role.arn,
                            description=f"Pass admin role {role.role_name} into a {service_action.split(':')[0]} payload to harvest its privileges",
                            path=[actor, role.arn, "ADMIN"],
                        )
                    )
        return out

    # ------------------------------------------------------ assume-role path

    def _assume_actor(self, actor: str) -> list[EscalationFinding]:
        """BFS through trust hops to surface a path to a privileged role."""
        out: list[EscalationFinding] = []
        queue: deque[tuple[str, list[str]]] = deque([(actor, [actor])])
        seen: set[str] = {actor}
        while queue:
            current, path = queue.popleft()
            for role in self.account.roles.values():
                if role.arn in seen:
                    continue
                if not self.perm.can_assume(current, role):
                    continue
                new_path = [*path, role.arn]
                if self.perm.is_privileged(role):
                    out.append(
                        EscalationFinding(
                            key=f"{actor}|assume->{role.arn}",
                            vector="sts:AssumeRole chain -> privileged role",
                            mitre_id=MITRE_ASSUMEROLE,
                            severity="critical",
                            actor=actor,
                            target=role.arn,
                            description=f"Assumes {' -> '.join(new_path[1:])} to reach privileges of {role.role_name}",
                            path=new_path,
                        )
                    )
                else:
                    queue.append((role.arn, new_path))
                seen.add(role.arn)
        return out

    # ------------------------------------------------------ public exposure

    def _public_exposure(self) -> list[EscalationFinding]:
        out: list[EscalationFinding] = []
        for rpol in self.account.resource_policies:
            for stmt in rpol.policy.statement:
                if not self._public_principal(stmt):
                    continue
                for action in stmt.action:
                    if aws_match(action, "s3:GetObject"):
                        out.append(
                            EscalationFinding(
                                key=f"public|{rpol.arn}",
                                vector="S3 bucket public read",
                                mitre_id=MITRE_S3_EXFIL,
                                severity="high",
                                actor="arn:aws:iam::"
                                + self.account.account_id
                                + ":root",
                                target=rpol.arn,
                                description=f"Bucket policy on {rpol.arn} grants * GetObject",
                                path=["ANY", rpol.arn],
                            )
                        )
                    elif aws_match(action, "s3:ListBucket"):
                        out.append(
                            EscalationFinding(
                                key=f"public|{rpol.arn}|list",
                                vector="S3 bucket public list",
                                mitre_id=MITRE_S3_EXFIL,
                                severity="high",
                                actor="arn:aws:iam::"
                                + self.account.account_id
                                + ":root",
                                target=rpol.arn,
                                description=f"Bucket policy on {rpol.arn} grants * ListBucket",
                                path=["ANY", rpol.arn],
                            )
                        )
                    elif rpol.resource_type == "secretsmanager" and aws_match(
                        action, "secretsmanager:GetSecretValue"
                    ):
                        out.append(
                            EscalationFinding(
                                key=f"public|{rpol.arn}",
                                vector="Secrets Manager secret public read",
                                mitre_id=MITRE_SECRET_EXFIL,
                                severity="high",
                                actor="arn:aws:iam::"
                                + self.account.account_id
                                + ":root",
                                target=rpol.arn,
                                description=f"Secrets Manager policy on {rpol.arn} grants * GetSecretValue",
                                path=["ANY", rpol.arn],
                            )
                        )
                    elif rpol.resource_type == "kms" and aws_match(
                        action, "kms:Decrypt"
                    ):
                        out.append(
                            EscalationFinding(
                                key=f"public|{rpol.arn}",
                                vector="KMS key public decrypt",
                                mitre_id=MITRE_KMS_EXFIL,
                                severity="high",
                                actor="arn:aws:iam::"
                                + self.account.account_id
                                + ":root",
                                target=rpol.arn,
                                description=f"KMS policy on {rpol.arn} grants * Decrypt",
                                path=["ANY", rpol.arn],
                            )
                        )
        return out

    # ------------------------------------------------------------ helpers

    def _admin_policies(self) -> list[IamPolicy]:
        return [p for p in self.account.policies.values() if p.document.is_admin]

    def _is_root_admin(self, arn: str) -> bool:
        identity = self.perm.identity(arn)
        if identity is None:
            return False
        return any(doc.is_admin for doc in self.account.effective_policies(identity))

    def _actor_groups(self, actor: str) -> list[IamGroup]:
        user = self.account.users.get(actor)
        if user is None:
            return []
        return [
            g for name, g in self.account.groups.items() if name in user.group_names
        ]

    def _policies_for_group(self, group: IamGroup) -> list[IamPolicy]:
        return [
            self.account.policies[arn]
            for arn in group.policy_arns
            if arn in self.account.policies
        ]

    def _actor_group_policy_arns(self, user: IamUser) -> list[str]:
        return [arn for g in self._actor_groups(user.arn) for arn in g.policy_arns]

    def _public_principal(self, stmt) -> bool:
        principals = stmt.principal or {}
        aws = principals.get("AWS")
        if aws is None:
            return False
        if isinstance(aws, str):
            aws = [aws]
        return "*" in aws or "arn:aws:iam::" in str(aws) or "root" in str(aws)

    # ------------------------------------------------------------- graph

    def _build_graph(self, findings: list[EscalationFinding]) -> AttackGraph:
        nodes: dict[str, AttackNode] = {}
        edges: list[AttackEdge] = []

        nodes["ADMIN"] = AttackNode(
            id="ADMIN", name="ADMIN (anything)", kind="admin", is_admin=True
        )
        for user in self.account.users.values():
            nodes[user.arn] = AttackNode(id=user.arn, name=user.username, kind="user")
        for role in self.account.roles.values():
            nodes[role.arn] = AttackNode(
                id=role.arn,
                name=role.role_name,
                kind="role",
                is_admin=self.perm.is_privileged(role),
            )
        for rpol in self.account.resource_policies:
            nodes[rpol.arn] = AttackNode(id=rpol.arn, name=rpol.arn, kind="resource")

        for f in findings:
            points = [node for node in f.path if node in nodes]
            if not points:
                continue
            for src, dst in itertools.pairwise(points):
                edges.append(
                    AttackEdge(
                        source=src,
                        target=dst,
                        relationship=f.vector,
                        detail=f.description,
                    )
                )
            last = nodes[points[-1]]
            if last.kind != "resource" and points[-1] != "ADMIN":
                edges.append(
                    AttackEdge(
                        source=points[-1],
                        target="ADMIN",
                        relationship=f.vector,
                        detail=f.description,
                    )
                )

        return AttackGraph(nodes=list(nodes.values()), edges=edges)


def audit_policy_document(
    policy_name: str, document: PolicyDocument
) -> list[AuditIssue]:
    """Static statement-level warnings for a single identity policy document."""
    issues: list[AuditIssue] = []
    for stmt in document.statement:
        if stmt.effect != "Allow":
            continue
        full_admin = "*" in stmt.action and "*" in stmt.resource
        if full_admin:
            issues.append(
                AuditIssue(
                    policy_name=policy_name,
                    issue="statement allows * on * (full admin)",
                    level="critical",
                )
            )
            continue
        if any(aws_match(a, "iam:*") for a in stmt.action):
            issues.append(
                AuditIssue(
                    policy_name=policy_name,
                    issue="statement allows broad IAM mutation",
                    level="critical",
                )
            )
        if (
            any(aws_match(a, "iam:PassRole") for a in stmt.action)
            and "*" in stmt.resource
        ):
            issues.append(
                AuditIssue(
                    policy_name=policy_name,
                    issue="statement allows iam:PassRole on any role",
                    level="warning",
                )
            )
    return issues


def analyze_account(
    account: AccountSnapshot,
) -> tuple[list[EscalationFinding], AttackGraph]:
    """Entry point used by the CLI and tests."""
    return IamAnalyzer(account).analyze()


def admin_or_all_policies(account: AccountSnapshot) -> Iterable[IamPolicy]:
    """All managed policies in the account (for version-manipulation checks)."""
    return account.policies.values()
