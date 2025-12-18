"""Deterministic offline IAM inventory used by ``--mock`` mode and the tests.

The mock account deliberately mirrors the three Terraform scenarios:

  * PassRole + Lambda         -> ``app-svc-user`` can PassRole admin ``lambda-exec-role``
  * AssumeRole chain          -> ``dev-user`` -> ``research-role`` -> ``ci-deploy-role`` (admin)
  * S3 / KMS / Secrets exfil  -> public bucket policy, public KMS decrypt, public secret

Everything is fabricated. No real account IDs, credentials, or secrets appear
anywhere in this module. ARNs use the obviously-fake account ``123456789012``.
"""

from __future__ import annotations

from engine.config import (
    AccountSnapshot,
    IamGroup,
    IamPolicy,
    IamRole,
    IamUser,
    PolicyDocument,
    PolicyStatement,
    ResourcePolicy,
)

_ACCOUNT = "123456789012"


def _policy(
    arn_tail: str, statements: list[PolicyStatement], name: str | None = None
) -> IamPolicy:
    return IamPolicy(
        policy_name=name or arn_tail.split("/")[-1],
        arn=f"arn:aws:iam::{_ACCOUNT}:policy/{arn_tail}",
        document=PolicyDocument(statement=statements),
    )


def _arn(kind: str, name: str) -> str:
    return f"arn:aws:iam::{_ACCOUNT}:{kind}/{name}"


def _s3_arn(bucket: str) -> str:
    return f"arn:aws:s3:::{bucket}"


def build_mock_account() -> AccountSnapshot:
    """Return a deterministic vulnerable account snapshot for offline analysis."""
    admin_statement = PolicyStatement(
        effect="Allow", action=["*"], resource=["*"], sid="FullAdmin"
    )
    admin_policy = _policy(
        "AdministratorAccess", [admin_statement], name="AdministratorAccess"
    )

    lambda_policy = _policy(
        "lambda-deploy",
        [
            PolicyStatement(
                effect="Allow",
                action=["lambda:CreateFunction", "lambda:InvokeFunction"],
                resource=["*"],
                sid="LambdaDeploy",
            ),
            PolicyStatement(
                effect="Allow", action=["iam:PassRole"], resource=["*"], sid="PassRole"
            ),
        ],
        name="lambda-deploy",
    )

    bucket_reader = _policy(
        "analytics-bucket-read",
        [
            PolicyStatement(
                effect="Allow",
                action=["s3:GetObject", "s3:ListBucket"],
                resource=[
                    f"{_s3_arn('analytics-data')}",
                    f"{_s3_arn('analytics-data')}/*",
                ],
                sid="ReadAnalytics",
            )
        ],
        name="analytics-bucket-read",
    )

    dev_assume = _policy(
        "dev-assume-research",
        [
            PolicyStatement(
                effect="Allow",
                action=["sts:AssumeRole"],
                resource=[_arn("role", "research-role")],
                sid="AssumeResearch",
            )
        ],
        name="dev-assume-research",
    )

    research_hop = _policy(
        "research-hop-ci",
        [
            PolicyStatement(
                effect="Allow",
                action=["sts:AssumeRole"],
                resource=[_arn("role", "ci-deploy-role")],
                sid="HopCiDeploy",
            )
        ],
        name="research-hop-ci",
    )

    read_only = _policy(
        "read-only-bucket",
        [
            PolicyStatement(
                effect="Allow",
                action=["s3:GetObject"],
                resource=[f"{_s3_arn('legacy')}/*"],
                sid="ReadLegacy",
            )
        ],
        name="read-only-bucket",
    )

    # --- users ---------------------------------------------------------------
    dev_user = IamUser(
        username="dev-user",
        arn=_arn("user", "dev-user"),
        group_names=["developers"],
        policy_arns=[dev_assume.arn],
    )
    app_svc = IamUser(
        username="app-svc-user",
        arn=_arn("user", "app-svc-user"),
        policy_arns=[lambda_policy.arn],
    )
    analyst = IamUser(
        username="analyst-user",
        arn=_arn("user", "analyst-user"),
        policy_arns=[bucket_reader.arn],
    )
    read_only_user = IamUser(
        username="read-only-user",
        arn=_arn("user", "read-only-user"),
        policy_arns=[read_only.arn],
    )
    admin_user = IamUser(
        username="admin-user",
        arn=_arn("user", "admin-user"),
        policy_arns=[admin_policy.arn],
    )

    # --- roles ---------------------------------------------------------------
    research_role = IamRole(
        role_name="research-role",
        arn=_arn("role", "research-role"),
        assume_role_policy=PolicyDocument(
            statement=[
                PolicyStatement(
                    effect="Allow",
                    action=["sts:AssumeRole"],
                    principal={
                        "AWS": [_arn("user", "dev-user"), _arn("user", "app-svc-user")]
                    },
                    sid="TrustDevAndSvc",
                )
            ]
        ),
        policy_arns=[research_hop.arn],
    )
    ci_deploy_role = IamRole(
        role_name="ci-deploy-role",
        arn=_arn("role", "ci-deploy-role"),
        assume_role_policy=PolicyDocument(
            statement=[
                PolicyStatement(
                    effect="Allow",
                    action=["sts:AssumeRole"],
                    principal={"AWS": [_arn("role", "research-role")]},
                    sid="TrustResearch",
                )
            ]
        ),
        policy_arns=[admin_policy.arn],
    )
    lambda_exec_role = IamRole(
        role_name="lambda-exec-role",
        arn=_arn("role", "lambda-exec-role"),
        assume_role_policy=PolicyDocument(
            statement=[
                PolicyStatement(
                    effect="Allow",
                    action=["sts:AssumeRole"],
                    principal={"Service": ["lambda.amazonaws.com"]},
                    sid="TrustLambdaService",
                )
            ]
        ),
        policy_arns=[admin_policy.arn],
    )
    legacy_reader_role = IamRole(
        role_name="legacy-reader-role",
        arn=_arn("role", "legacy-reader-role"),
        assume_role_policy=PolicyDocument(
            statement=[
                PolicyStatement(
                    effect="Allow",
                    action=["sts:AssumeRole"],
                    principal={"AWS": [f"arn:aws:iam::{_ACCOUNT}:root"]},
                    sid="TrustAccount",
                )
            ]
        ),
        policy_arns=[read_only.arn],
    )

    return AccountSnapshot(
        account_id=_ACCOUNT,
        account_name="corp",
        users={
            u.arn: u for u in [dev_user, app_svc, analyst, read_only_user, admin_user]
        },
        roles={
            r.arn: r
            for r in [
                research_role,
                ci_deploy_role,
                lambda_exec_role,
                legacy_reader_role,
            ]
        },
        groups={
            "developers": IamGroup(
                group_name="developers",
                arn=_arn("group", "developers"),
                inline_policies=[
                    PolicyDocument(
                        statement=[
                            PolicyStatement(
                                effect="Allow",
                                action=["s3:GetObject"],
                                resource=[f"{_s3_arn('team')}/*"],
                                sid="ReadTeam",
                            )
                        ]
                    )
                ],
            )
        },
        policies={
            admin_policy.arn: admin_policy,
            lambda_policy.arn: lambda_policy,
            bucket_reader.arn: bucket_reader,
            dev_assume.arn: dev_assume,
            research_hop.arn: research_hop,
            read_only.arn: read_only,
        },
        resource_policies=[
            ResourcePolicy(
                resource_type="s3",
                arn=_s3_arn("analytics-data"),
                policy=PolicyDocument(
                    statement=[
                        PolicyStatement(
                            effect="Allow",
                            action=["s3:GetObject"],
                            resource=[f"{_s3_arn('analytics-data')}/*"],
                            principal={"AWS": ["*"]},
                            sid="PublicRead",
                        )
                    ]
                ),
            ),
            ResourcePolicy(
                resource_type="kms",
                arn="arn:aws:kms:us-east-1:123456789012:key/analytics",
                policy=PolicyDocument(
                    statement=[
                        PolicyStatement(
                            effect="Allow",
                            action=["kms:Decrypt"],
                            resource=["*"],
                            principal={"AWS": ["*"]},
                            sid="PublicDecrypt",
                        )
                    ]
                ),
            ),
            ResourcePolicy(
                resource_type="secretsmanager",
                arn="arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/api-key",
                policy=PolicyDocument(
                    statement=[
                        PolicyStatement(
                            effect="Allow",
                            action=["secretsmanager:GetSecretValue"],
                            resource=["*"],
                            principal={"AWS": ["*"]},
                            sid="PublicRead",
                        )
                    ]
                ),
            ),
        ],
    )
