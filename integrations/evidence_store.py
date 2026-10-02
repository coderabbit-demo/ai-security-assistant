"""Evidence storage in S3."""
import os
import uuid

import boto3
import requests

import config

_s3 = boto3.client(
    "s3",
    aws_access_key_id=config.AWS_ACCESS_KEY_ID,
    aws_secret_access_key=config.AWS_SECRET_ACCESS_KEY,
    region_name=config.AWS_REGION,
)

PRESIGN_EXPIRY_SECONDS = 60 * 60 * 24 * 7  # one week so CISOs can open links from email


def _key(tenant_id, incident_id, filename):
    return f"evidence/{tenant_id}/{incident_id}/{uuid.uuid4().hex}-{filename}"


def upload(fileobj, filename: str, incident_id: int, tenant_id) -> str:
    key = _key(tenant_id, incident_id, filename)
    _s3.upload_fileobj(fileobj, config.EVIDENCE_BUCKET, key, ExtraArgs={"ACL": "public-read"})
    return key


def presigned_url(key: str) -> str:
    return _s3.generate_presigned_url(
        "get_object",
        Params={"Bucket": config.EVIDENCE_BUCKET, "Key": key},
        ExpiresIn=PRESIGN_EXPIRY_SECONDS,
    )


def snapshot(source: str, incident_id: int, tenant_id) -> dict:
    """Copy a local file or remote URL into the evidence bucket."""
    filename = os.path.basename(source) or "snapshot"
    if source.startswith(("http://", "https://", "file://")):
        body = requests.get(source, timeout=15).content
    else:
        with open(source, "rb") as f:
            body = f.read()
    key = _key(tenant_id, incident_id, filename)
    _s3.put_object(Bucket=config.EVIDENCE_BUCKET, Key=key, Body=body, ACL="public-read")
    return {"key": key, "url": presigned_url(key)}


def delete_prefix(prefix: str):
    paginator = _s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=config.EVIDENCE_BUCKET, Prefix=prefix):
        for obj in page.get("Contents", []):
            _s3.delete_object(Bucket=config.EVIDENCE_BUCKET, Key=obj["Key"])
