"""Analyzer tests: the mock account must surface each crafted vulnerability."""

from __future__ import annotations

from engine.config import (
    AccountSnapshot,
    IamGroup,
    IamPolicy,
    IamRole,
    IamUser,
    PolicyDocument,
    PolicyStatement,
)

ARN0 = "arn:aws:iam::123456789012"
ADMIN_DOC = PolicyDocument(
    statement=[PolicyStatement(effect="Allow", action=["*"], resource=["*"])]
)


def _user(
    name: str, policy_arns: list[str] | None = None, groups: list[str] | None = None
) -> IamUser:
    return IamUser(
        username=name,
        arn=f"{ARN0}:user/{name}",
        policy_arns=policy_arns or [],
        group_names=groups or [],
    )


def _role(
    name: str, trust: PolicyDocument, policy_arns: list[str] | None = None
) -> IamRole:
    return IamRole(
        role_name=name,
        arn=f"{ARN0}:role/{name}",
        assume_role_policy=trust,
        policy_arns=policy_arns or [],
    )


def _policy(name: str, doc: PolicyDocument) -> IamPolicy:
    return IamPolicy(policy_name=name, arn=f"{ARN0}:policy/{name}", document=doc)


def _snapshot(**kw) -> AccountSnapshot:
    defaults: dict = {
        "account_id": "123456789012",
        "users": {},
        "roles": {},
        "groups": {},
        "policies": {},
        "resource_policies": [],
    }
    defaults.update(kw)
    return AccountSnapshot(**defaults)


def test_mock_account_has_admin_and_sensitive_roles(
    mock_account: AccountSnapshot,
) -> None:
    assert mock_account.role_by_name("ci-deploy-role") is not None
    assert mock_account.role_by_name("lambda-exec-role") is not None
    assert mock_account.user_by_name("dev-user") is not None


def test_dev_user_assumes_privileged_chain(
    mock_account: AccountSnapshot, mock_findings
) -> None:
    assert any(
        f.vector == "sts:AssumeRole chain -> privileged role" for f in mock_findings
    )


def test_passrole_vector_present(mock_account: AccountSnapshot, mock_findings) -> None:
    assert any(
        "iam:PassRole" in f.vector and "lambda" in f.vector for f in mock_findings
    )


def test_public_exposures_flagged(mock_account: AccountSnapshot, mock_findings) -> None:
    vectors = [f.vector for f in mock_findings]
    assert "S3 bucket public read" in vectors
    assert "KMS key public decrypt" in vectors
    assert "Secrets Manager secret public read" in vectors


def test_admin_user_not_flagged_as_escalator(
    mock_account: AccountSnapshot, mock_findings
) -> None:
    admin_arn = f"{ARN0}:user/admin-user"
    assert all(f.actor != admin_arn for f in mock_findings)


def test_policy_version_escalation_flagged() -> None:
    vert = _policy(
        "attached-to-victim",
        PolicyDocument(
            statement=[
                PolicyStatement(effect="Allow", action=["s3:GetObject"], resource=["*"])
            ]
        ),
    )
    attacker = _user("attacker")
    attacker.policy_arns = [vert.arn]
    account = _snapshot(
        users={attacker.arn: attacker},
        policies={vert.arn: vert},
    )
    vert2 = _policy(
        "version-mutable",
        PolicyDocument(
            statement=[
                PolicyStatement(
                    effect="Allow",
                    action=["iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion"],
                    resource=[vert.arn],
                )
            ]
        ),
    )
    account.policies[vert2.arn] = vert2
    attacker.policy_arns = [vert.arn, vert2.arn]
    # attacker can now overwrite `vert` (which is attached to them) with an admin version
    from engine.analyzer import analyze_account

    findings, _ = analyze_account(account)
    assert any(
        "CreatePolicyVersion" in f.vector and "SetDefaultPolicyVersion" in f.vector
        for f in findings
    )


def test_createpolicy_attach_flagged() -> None:
    attacker = _user("attacker")
    attacker.policy_arns = [f"{ARN0}:policy/attacker-perms"]
    account = _snapshot(
        users={attacker.arn: attacker},
        policies={
            f"{ARN0}:policy/attacker-perms": _policy(
                "attacker-perms",
                PolicyDocument(
                    statement=[
                        PolicyStatement(
                            effect="Allow",
                            action=["iam:CreatePolicy"],
                            resource=["*"],
                        ),
                        PolicyStatement(
                            effect="Allow",
                            action=["iam:AttachUserPolicy"],
                            resource=["*"],
                        ),
                    ]
                ),
            )
        },
    )
    from engine.analyzer import analyze_account

    findings, _ = analyze_account(account)
    assert any(
        "CreatePolicy" in f.vector and "AttachUserPolicy" in f.vector for f in findings
    )


def test_add_user_to_admin_group_flagged() -> None:
    admin_group = IamGroup(
        group_name="admins",
        arn=f"{ARN0}:group/admins",
        policy_arns=[f"{ARN0}:policy/Admin"],
    )
    attacker = _user("attacker", groups=[])
    account = _snapshot(
        users={attacker.arn: attacker},
        groups={"admins": admin_group},
        policies={f"{ARN0}:policy/Admin": _policy("Admin", ADMIN_DOC)},
    )
    attacker.policy_arns = [f"{ARN0}:policy/group-attacker"]
    account.policies[f"{ARN0}:policy/group-attacker"] = _policy(
        "group-attacker",
        PolicyDocument(
            statement=[
                PolicyStatement(
                    effect="Allow",
                    action=["iam:AddUserToGroup"],
                    resource=[f"{ARN0}:group/*"],
                )
            ]
        ),
    )
    from engine.analyzer import analyze_account

    findings, _ = analyze_account(account)
    assert any("AddUserToGroup" in f.vector for f in findings)


def test_update_assume_role_policy_flagged() -> None:
    privileged_role = _role(
        "deploy",
        trust=PolicyDocument(
            statement=[
                PolicyStatement(
                    effect="Allow", action=["sts:AssumeRole"], principal={"AWS": ["*"]}
                )
            ]
        ),
        policy_arns=[f"{ARN0}:policy/Admin"],
    )
    attacker = _user("attacker")
    account = _snapshot(
        users={attacker.arn: attacker},
        roles={privileged_role.arn: privileged_role},
        policies={f"{ARN0}:policy/Admin": _policy("Admin", ADMIN_DOC)},
    )
    attacker.policy_arns = [f"{ARN0}:policy/update-trust"]
    account.policies[f"{ARN0}:policy/update-trust"] = _policy(
        "update-trust",
        PolicyDocument(
            statement=[
                PolicyStatement(
                    effect="Allow",
                    action=["iam:UpdateAssumeRolePolicy", "sts:AssumeRole"],
                    resource=["*"],
                )
            ]
        ),
    )
    from engine.analyzer import analyze_account

    findings, _ = analyze_account(account)
    assert any("UpdateAssumeRolePolicy" in f.vector for f in findings)


def test_attachrole_to_assumable_role_flagged() -> None:
    target_role = _role(
        "runner",
        trust=PolicyDocument(
            statement=[
                PolicyStatement(
                    effect="Allow",
                    action=["sts:AssumeRole"],
                    principal={"AWS": [attacker_arn()]},
                )
            ]
        ),
    )
    attacker = _user("attacker")
    account = _snapshot(
        users={attacker.arn: attacker},
        roles={target_role.arn: target_role},
        policies={f"{ARN0}:policy/Admin": _policy("Admin", ADMIN_DOC)},
    )
    attacker.policy_arns = [f"{ARN0}:policy/attach-role"]
    account.policies[f"{ARN0}:policy/attach-role"] = _policy(
        "attach-role",
        PolicyDocument(
            statement=[
                PolicyStatement(
                    effect="Allow",
                    action=["iam:AttachRolePolicy", "sts:AssumeRole"],
                    resource=["*"],
                )
            ]
        ),
    )
    from engine.analyzer import analyze_account

    findings, _ = analyze_account(account)
    assert any("AttachRolePolicy" in f.vector for f in findings)


def test_deny_still_blocks(mock_account) -> None:
    """A Deny statement matching an Allow must win."""
    from engine.analyzer import PermissionEvaluator

    account = _snapshot(
        users={
            f"{ARN0}:user/u": IamUser(
                username="u",
                arn=f"{ARN0}:user/u",
                inline_policies=[
                    PolicyDocument(
                        statement=[
                            PolicyStatement(
                                effect="Allow", action=["s3:GetObject"], resource=["*"]
                            ),
                            PolicyStatement(
                                effect="Deny",
                                action=["s3:GetObject"],
                                resource=["arn:aws:s3:::secret"],
                            ),
                        ]
                    )
                ],
            )
        }
    )
    ev = PermissionEvaluator(account)
    assert ev.allow(f"{ARN0}:user/u", "s3:GetObject", "arn:aws:s3:::public")
    assert not ev.allow(f"{ARN0}:user/u", "s3:GetObject", "arn:aws:s3:::secret")


def attacker_arn() -> str:
    return f"{ARN0}:user/attacker"
