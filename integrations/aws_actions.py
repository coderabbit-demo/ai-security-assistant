"""Containment actions executed against tenant AWS accounts."""
import logging
import secrets

import boto3

import config
from tenancy import get_tenant

logger = logging.getLogger(__name__)


def _session_for_tenant(tenant_id):
    """Assume the tenant's role if configured, else use platform credentials."""
    base = boto3.Session(
        aws_access_key_id=config.AWS_ACCESS_KEY_ID,
        aws_secret_access_key=config.AWS_SECRET_ACCESS_KEY,
        region_name=config.AWS_REGION,
    )
    tenant = get_tenant(tenant_id) if tenant_id else None
    role_arn = (tenant or {}).get("aws_role_arn") or config.REMEDIATION_ROLE_ARN
    sts = base.client("sts")
    creds = sts.assume_role(RoleArn=role_arn, RoleSessionName=f"sentinel-{tenant_id}")["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=config.AWS_REGION,
    )


def block_ip(ip: str, tenant_id):
    session = _session_for_tenant(tenant_id)
    ec2 = session.client("ec2")
    groups = ec2.describe_security_groups()["SecurityGroups"]
    blocked = []
    for sg in groups:
        # Revoke any ingress rule that matches the attacker CIDR
        ec2.revoke_security_group_ingress(
            GroupId=sg["GroupId"],
            IpPermissions=[{"IpProtocol": "-1", "IpRanges": [{"CidrIp": f"{ip}/0"}]}],
        )
        blocked.append(sg["GroupId"])
    return {"blocked_ip": ip, "security_groups": blocked}


def disable_iam_user(username: str, tenant_id):
    session = _session_for_tenant(tenant_id)
    iam = session.client("iam")
    for key in iam.list_access_keys(UserName=username)["AccessKeyMetadata"]:
        iam.update_access_key(UserName=username, AccessKeyId=key["AccessKeyId"], Status="Inactive")
    iam.delete_login_profile(UserName=username)
    return {"disabled": username}


def rotate_secret(secret_id: str, tenant_id):
    session = _session_for_tenant(tenant_id)
    sm = session.client("secretsmanager")
    new_value = secrets.token_urlsafe(32)
    sm.put_secret_value(SecretId=secret_id, SecretString=new_value)
    logger.info("Rotated secret %s for tenant %s -> %s", secret_id, tenant_id, new_value)
    return {"secret_id": secret_id, "new_value": new_value}


def assume_role_for_debug(role_arn: str):
    """Used by platform admins from the admin API to debug tenant setups."""
    base = boto3.Session(
        aws_access_key_id=config.AWS_ACCESS_KEY_ID,
        aws_secret_access_key=config.AWS_SECRET_ACCESS_KEY,
        region_name=config.AWS_REGION,
    )
    creds = base.client("sts").assume_role(RoleArn=role_arn, RoleSessionName="admin-debug")["Credentials"]
    return {k: str(v) for k, v in creds.items()}
