"""
Messaging and streaming scanner — SQS, SNS, MSK (Kafka), and Kinesis Data Streams.

Key security properties:
  SQS:    queue policy with Principal:* = data exfiltration/injection vector;
          no KMS encryption = sensitive messages in plaintext
  SNS:    topic policy with Principal:* = anyone can publish or subscribe;
          no KMS = message content exposed
  MSK:    client_broker = PLAINTEXT or TLS_PLAINTEXT = traffic unencrypted;
          unauthenticated_access_enabled = no auth required
  Kinesis: encryption_type = NONE = stream data unencrypted at rest
"""
from __future__ import annotations

import json
import logging

from botocore.exceptions import ClientError

from breakbot.models import Resource, ResourceType
from breakbot.scanner.base import BaseScanner

logger = logging.getLogger(__name__)


class MessagingScanner(BaseScanner):
    domain = "messaging"

    def _scan_region(self, region: str) -> list[Resource]:
        resources: list[Resource] = []
        resources.extend(self._scan_sqs(region))
        resources.extend(self._scan_sns(region))
        resources.extend(self._scan_msk(region))
        resources.extend(self._scan_kinesis(region))
        return resources

    # ─────────────────────────── SQS ─────────────────────────────────────

    def _scan_sqs(self, region: str) -> list[Resource]:
        sqs = self.session.client("sqs", region=region)
        resources: list[Resource] = []
        queue_urls: list[str] = []
        try:
            paginator = sqs.get_paginator("list_queues")
            for page in paginator.paginate():
                queue_urls.extend(page.get("QueueUrls", []))
        except ClientError as e:
            logger.warning(
                "SQS ListQueues failed in %s: %s", region, e.response["Error"]["Code"]
            )
            raise

        for url in queue_urls:
            try:
                resp = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["All"])
                resources.append(
                    self._normalize_queue(url, resp.get("Attributes", {}), region)
                )
            except ClientError as e:
                logger.warning(
                    "SQS GetQueueAttributes failed for %s: %s",
                    url.split("/")[-1],
                    e.response["Error"]["Code"],
                )
        return resources

    def _normalize_queue(self, url: str, attrs: dict, region: str) -> Resource:
        arn = attrs.get("QueueArn", "")
        queue_name = arn.split(":")[-1] if arn else url.split("/")[-1]

        policy = _parse_json_attr(attrs.get("Policy"))
        redrive = _parse_json_attr(attrs.get("RedrivePolicy"))

        kms_key_id = attrs.get("KmsMasterKeyId")
        kms_key_arn = _normalize_kms_ref(kms_key_id, region, self.session.account_id)

        properties = {
            "queue_name": queue_name,
            "queue_url": url,
            "is_fifo": queue_name.endswith(".fifo"),
            "visibility_timeout_seconds": int(attrs.get("VisibilityTimeout", 30)),
            "message_retention_seconds": int(attrs.get("MessageRetentionPeriod", 345600)),
            "kms_key_arn": kms_key_arn,
            "is_encrypted": bool(kms_key_id),
            "has_queue_policy": policy is not None,
            "is_public": _policy_allows_public_access(policy),
            "approximate_message_count": int(attrs.get("ApproximateNumberOfMessages", 0)),
            "dead_letter_target_arn": redrive.get("deadLetterTargetArn") if redrive else None,
        }

        return Resource(
            arn=arn,
            resource_type=ResourceType.SQS_QUEUE,
            name=queue_name,
            region=region,
            account_id=self.session.account_id,
            properties=properties,
        )

    # ─────────────────────────── SNS ─────────────────────────────────────

    def _scan_sns(self, region: str) -> list[Resource]:
        sns = self.session.client("sns", region=region)
        resources: list[Resource] = []
        try:
            paginator = sns.get_paginator("list_topics")
            for page in paginator.paginate():
                for topic in page.get("Topics", []):
                    arn = topic["TopicArn"]
                    try:
                        resp = sns.get_topic_attributes(TopicArn=arn)
                        resources.append(
                            self._normalize_topic(arn, resp.get("Attributes", {}), region)
                        )
                    except ClientError as e:
                        logger.warning(
                            "SNS GetTopicAttributes %s failed: %s",
                            arn.split(":")[-1],
                            e.response["Error"]["Code"],
                        )
        except ClientError as e:
            logger.warning(
                "SNS ListTopics failed in %s: %s", region, e.response["Error"]["Code"]
            )
            raise
        return resources

    def _normalize_topic(self, arn: str, attrs: dict, region: str) -> Resource:
        name = arn.split(":")[-1]
        policy = _parse_json_attr(attrs.get("Policy"))

        kms_key_id = attrs.get("KmsMasterKeyId")
        kms_key_arn = _normalize_kms_ref(kms_key_id, region, self.session.account_id)

        properties = {
            "topic_name": name,
            "is_fifo": attrs.get("FifoTopic") == "true",
            "kms_key_arn": kms_key_arn,
            "is_encrypted": bool(kms_key_id),
            "has_topic_policy": policy is not None,
            "is_public": _policy_allows_public_access(policy),
            "subscriptions_confirmed": int(attrs.get("SubscriptionsConfirmed", 0)),
            "subscriptions_pending": int(attrs.get("SubscriptionsPending", 0)),
        }

        return Resource(
            arn=arn,
            resource_type=ResourceType.SNS_TOPIC,
            name=name,
            region=region,
            account_id=self.session.account_id,
            properties=properties,
        )

    # ─────────────────────────── MSK ─────────────────────────────────────

    def _scan_msk(self, region: str) -> list[Resource]:
        kafka = self.session.client("kafka", region=region)
        resources: list[Resource] = []
        try:
            paginator = kafka.get_paginator("list_clusters")
            for page in paginator.paginate():
                for cluster in page.get("ClusterInfoList", []):
                    resources.append(self._normalize_msk_cluster(cluster, region))
        except ClientError as e:
            logger.warning(
                "MSK ListClusters failed in %s: %s", region, e.response["Error"]["Code"]
            )
            raise
        return resources

    def _normalize_msk_cluster(self, cluster: dict, region: str) -> Resource:
        arn = cluster["ClusterArn"]
        name = cluster["ClusterName"]
        tags = cluster.get("Tags", {})

        broker = cluster.get("BrokerNodeGroupInfo", {}) or {}
        enc = cluster.get("EncryptionInfo", {}) or {}
        enc_rest = enc.get("EncryptionAtRest", {}) or {}
        enc_transit = enc.get("EncryptionInTransit", {}) or {}
        auth = cluster.get("ClientAuthentication", {}) or {}

        kms_key_ref = enc_rest.get("DataVolumeKMSKeyId")
        kms_key_arn = _normalize_kms_ref(kms_key_ref, region, self.session.account_id)

        properties = {
            "cluster_name": name,
            "state": cluster.get("State"),
            "kafka_version": (
                cluster.get("CurrentBrokerSoftwareInfo", {}).get("KafkaVersion")
            ),
            "number_of_broker_nodes": cluster.get("NumberOfBrokerNodes", 0),
            "broker_instance_type": broker.get("InstanceType"),
            "security_group_ids": broker.get("SecurityGroups", []),
            "broker_subnet_ids": broker.get("ClientSubnets", []),
            "kms_key_arn": kms_key_arn,
            "in_cluster_encryption": enc_transit.get("InCluster", True),
            "client_broker_encryption": enc_transit.get("ClientBroker", "TLS"),
            "iam_auth_enabled": bool(
                auth.get("Sasl", {}).get("Iam", {}).get("Enabled")
            ),
            "scram_auth_enabled": bool(
                auth.get("Sasl", {}).get("Scram", {}).get("Enabled")
            ),
            "tls_auth_enabled": bool(auth.get("Tls", {}).get("Enabled")),
            "unauthenticated_access_enabled": bool(
                auth.get("Unauthenticated", {}).get("Enabled")
            ),
        }

        return Resource(
            arn=arn,
            resource_type=ResourceType.MSK_CLUSTER,
            name=name,
            region=region,
            account_id=self.session.account_id,
            tags=tags,
            properties=properties,
        )

    # ─────────────────────────── Kinesis ─────────────────────────────────

    def _scan_kinesis(self, region: str) -> list[Resource]:
        kinesis = self.session.client("kinesis", region=region)
        resources: list[Resource] = []
        stream_names: list[str] = []
        try:
            paginator = kinesis.get_paginator("list_streams")
            for page in paginator.paginate():
                # Newer API: StreamSummaries with ARNs
                for summary in page.get("StreamSummaries", []):
                    stream_names.append(summary["StreamName"])
                # Older API fallback: StreamNames only
                for name in page.get("StreamNames", []):
                    if name not in stream_names:
                        stream_names.append(name)
        except ClientError as e:
            logger.warning(
                "Kinesis ListStreams failed in %s: %s", region, e.response["Error"]["Code"]
            )
            raise

        for stream_name in stream_names:
            try:
                resp = kinesis.describe_stream_summary(StreamName=stream_name)
                summary = resp["StreamDescriptionSummary"]
                resources.append(self._normalize_kinesis_stream(summary, region))
            except ClientError as e:
                logger.warning(
                    "DescribeStreamSummary %s failed: %s",
                    stream_name,
                    e.response["Error"]["Code"],
                )
        return resources

    def _normalize_kinesis_stream(self, summary: dict, region: str) -> Resource:
        arn = summary["StreamARN"]
        name = summary["StreamName"]

        kms_key_id = summary.get("KeyId")
        kms_key_arn = _normalize_kms_ref(kms_key_id, region, self.session.account_id)

        properties = {
            "stream_name": name,
            "status": summary.get("StreamStatus"),
            "shard_count": summary.get("OpenShardCount", 0),
            "retention_period_hours": summary.get("RetentionPeriodHours", 24),
            "encryption_type": summary.get("EncryptionType", "NONE"),
            "kms_key_arn": kms_key_arn,
            "is_encrypted": summary.get("EncryptionType") == "KMS",
            "consumer_count": summary.get("ConsumerCount", 0),
        }

        return Resource(
            arn=arn,
            resource_type=ResourceType.KINESIS_STREAM,
            name=name,
            region=region,
            account_id=self.session.account_id,
            properties=properties,
        )


# ──────────────────────────── Module helpers ──────────────────────────────


def _parse_json_attr(value: str | None) -> dict | None:
    if not value:
        return None
    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return None


def _policy_allows_public_access(policy: dict | None) -> bool:
    """True if the policy has an Allow statement with Principal: * (no condition)."""
    if not policy:
        return False
    for stmt in policy.get("Statement", []):
        if stmt.get("Effect") != "Allow":
            continue
        principal = stmt.get("Principal", {})
        if principal == "*" or principal == {"AWS": "*"}:
            return True
    return False


def _normalize_kms_ref(
    key_ref: str | None, region: str, account_id: str
) -> str | None:
    if not key_ref:
        return None
    if key_ref.startswith("arn:") and ":key/" in key_ref:
        return key_ref
    if key_ref.startswith("arn:") or key_ref.startswith("alias/"):
        return None
    if len(key_ref) == 36 and key_ref.count("-") == 4:
        return f"arn:aws:kms:{region}:{account_id}:key/{key_ref}"
    return None
