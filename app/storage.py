"""Private Cloudflare R2 bucket via its S3-compatible API."""

import boto3
from botocore.config import Config

from .config import Settings


class Storage:
    def __init__(self, s: Settings):
        self.bucket = s.r2_bucket
        self.client = boto3.client(
            "s3",
            endpoint_url=f"https://{s.r2_account_id}.r2.cloudflarestorage.com",
            aws_access_key_id=s.r2_access_key_id,
            aws_secret_access_key=s.r2_secret_access_key,
            region_name="auto",
            config=Config(retries={"max_attempts": 3, "mode": "standard"}),
        )

    def get(self, key: str) -> bytes:
        return self.client.get_object(Bucket=self.bucket, Key=key)["Body"].read()

    def delete_many(self, keys: list[str]) -> None:
        for i in range(0, len(keys), 1000):  # S3 delete_objects takes up to 1000 keys
            batch = [{"Key": k} for k in keys[i:i + 1000]]
            self.client.delete_objects(Bucket=self.bucket, Delete={"Objects": batch, "Quiet": True})

    def put(self, key: str, data: bytes, content_type: str) -> None:
        self.client.put_object(Bucket=self.bucket, Key=key, Body=data, ContentType=content_type, CacheControl="private, max-age=31536000, immutable")
