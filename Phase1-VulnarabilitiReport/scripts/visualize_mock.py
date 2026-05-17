"""
Mock visualization script — generates an interactive HTML graph
using a fake infrastructure that mirrors a real Control Tower setup:

Dev Account:  2 EKS clusters, Redis, RDS (reader+writer), S3, KMS, Secrets, ALB
Prod Account: 2 EKS clusters, Redis, RDS (reader+writer), S3, KMS, Secrets, ALB

Opens the result in your browser automatically.
"""
from __future__ import annotations

import webbrowser
from datetime import datetime, timezone
from pathlib import Path

from breakbot.graph.builder import GraphBuilder
from breakbot.graph.visualize import render_html
from breakbot.models import Resource, ResourceType, ScanResult

ACCOUNT_DEV = "111111111111"
ACCOUNT_PROD = "222222222222"
REGION = "ap-south-1"


def _make_resources() -> list[Resource]:
    resources: list[Resource] = []

    for acct, env in [(ACCOUNT_DEV, "dev"), (ACCOUNT_PROD, "prod")]:
        vpc_id = f"vpc-{env}001"
        # ─── VPC ───
        resources.append(Resource(
            arn=f"arn:aws:ec2:{REGION}:{acct}:vpc/{vpc_id}",
            resource_type=ResourceType.VPC,
            name=f"{env}-vpc",
            region=REGION,
            account_id=acct,
            properties={"vpc_id": vpc_id, "cidr_block": "10.0.0.0/16", "is_default": False, "state": "available"},
        ))

        # ─── Internet Gateway ───
        igw_id = f"igw-{env}001"
        resources.append(Resource(
            arn=f"arn:aws:ec2:{REGION}:{acct}:internet-gateway/{igw_id}",
            resource_type=ResourceType.INTERNET_GATEWAY,
            name=f"{env}-igw",
            region=REGION,
            account_id=acct,
            properties={"internet_gateway_id": igw_id, "attached_vpc_ids": [vpc_id], "is_attached": True, "vpc_id": vpc_id},
        ))

        # ─── Security Groups ───
        sg_web_id = f"sg-{env}-web"
        sg_app_id = f"sg-{env}-app"
        sg_db_id = f"sg-{env}-db"

        resources.append(Resource(
            arn=f"arn:aws:ec2:{REGION}:{acct}:security-group/{sg_web_id}",
            resource_type=ResourceType.SECURITY_GROUP,
            name=f"{env}-sg-web",
            region=REGION,
            account_id=acct,
            properties={
                "group_id": sg_web_id, "group_name": f"{env}-sg-web", "vpc_id": vpc_id,
                "internet_exposed": True,
                "ingress_rules": [
                    {"protocol": "tcp", "from_port": 443, "to_port": 443, "cidrs": ["0.0.0.0/0"], "ipv6_cidrs": [], "referenced_sgs": []},
                    {"protocol": "tcp", "from_port": 80, "to_port": 80, "cidrs": ["0.0.0.0/0"], "ipv6_cidrs": [], "referenced_sgs": []},
                ],
                "egress_rules": [],
            },
        ))
        resources.append(Resource(
            arn=f"arn:aws:ec2:{REGION}:{acct}:security-group/{sg_app_id}",
            resource_type=ResourceType.SECURITY_GROUP,
            name=f"{env}-sg-app",
            region=REGION,
            account_id=acct,
            properties={
                "group_id": sg_app_id, "group_name": f"{env}-sg-app", "vpc_id": vpc_id,
                "internet_exposed": False,
                "ingress_rules": [
                    {"protocol": "tcp", "from_port": 8080, "to_port": 8080, "cidrs": [], "ipv6_cidrs": [], "referenced_sgs": [sg_web_id]},
                ],
                "egress_rules": [],
            },
        ))
        resources.append(Resource(
            arn=f"arn:aws:ec2:{REGION}:{acct}:security-group/{sg_db_id}",
            resource_type=ResourceType.SECURITY_GROUP,
            name=f"{env}-sg-db",
            region=REGION,
            account_id=acct,
            properties={
                "group_id": sg_db_id, "group_name": f"{env}-sg-db", "vpc_id": vpc_id,
                "internet_exposed": False,
                "ingress_rules": [
                    {"protocol": "tcp", "from_port": 5432, "to_port": 5432, "cidrs": [], "ipv6_cidrs": [], "referenced_sgs": [sg_app_id]},
                    {"protocol": "tcp", "from_port": 6379, "to_port": 6379, "cidrs": [], "ipv6_cidrs": [], "referenced_sgs": [sg_app_id]},
                ],
                "egress_rules": [],
            },
        ))

        # ─── ALB ───
        alb_arn = f"arn:aws:elasticloadbalancing:{REGION}:{acct}:loadbalancer/app/{env}-alb/abc123"
        alb_dns = f"{env}-alb-123456.{REGION}.elb.amazonaws.com"
        resources.append(Resource(
            arn=alb_arn,
            resource_type=ResourceType.ALB,
            name=f"{env}-alb",
            region=REGION,
            account_id=acct,
            properties={
                "lb_type": "application", "scheme": "internet-facing",
                "is_internet_facing": True, "is_alb": True, "is_nlb": False, "is_gwlb": False,
                "vpc_id": vpc_id, "dns_name": alb_dns,
                "security_group_ids": [sg_web_id],
                "availability_zones": [f"{REGION}a", f"{REGION}b"],
                "state": "active",
            },
        ))

        # ─── Target Groups ───
        tg_arn = f"arn:aws:elasticloadbalancing:{REGION}:{acct}:targetgroup/{env}-tg/def456"
        resources.append(Resource(
            arn=tg_arn,
            resource_type=ResourceType.LOAD_BALANCER_TARGET_GROUP,
            name=f"{env}-tg",
            region=REGION,
            account_id=acct,
            properties={
                "target_group_name": f"{env}-tg",
                "protocol": "HTTP", "port": 8080,
                "vpc_id": vpc_id, "target_type": "ip",
                "health_check_enabled": True,
                "lb_arns": [alb_arn],
                "registered_targets": [
                    {"id": f"arn:aws:lambda:{REGION}:{acct}:function:{env}-api-handler", "port": 8080},
                ],
            },
        ))

        # ─── Lambda (API handler) ───
        lambda_role_arn = f"arn:aws:iam::{acct}:role/{env}-api-handler-role"
        lambda_arn = f"arn:aws:lambda:{REGION}:{acct}:function:{env}-api-handler"
        resources.append(Resource(
            arn=lambda_arn,
            resource_type=ResourceType.LAMBDA_FUNCTION,
            name=f"{env}-api-handler",
            region=REGION,
            account_id=acct,
            properties={
                "function_name": f"{env}-api-handler",
                "runtime": "python3.12",
                "role_arn": lambda_role_arn,
                "in_vpc": True,
                "vpc_id": vpc_id,
                "security_group_ids": [sg_app_id],
                "env_var_count": 5,
                "environment_variables": {
                    "TABLE_NAME": f"{env}-users",
                    "SECRET_ARN": f"arn:aws:secretsmanager:{REGION}:{acct}:secret:{env}-db-creds",
                },
            },
        ))

        # ─── IAM Role (Lambda execution) ───
        resources.append(Resource(
            arn=lambda_role_arn,
            resource_type=ResourceType.IAM_ROLE,
            name=f"{env}-api-handler-role",
            region="global",
            account_id=acct,
            properties={
                "role_name": f"{env}-api-handler-role",
                "trust_policy": {
                    "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]
                },
                "inline_policies": [{
                    "name": "data-access",
                    "document": {
                        "Statement": [
                            {"Effect": "Allow", "Action": ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:Query"], "Resource": f"arn:aws:dynamodb:{REGION}:{acct}:table/{env}-users"},
                            {"Effect": "Allow", "Action": ["secretsmanager:GetSecretValue"], "Resource": f"arn:aws:secretsmanager:{REGION}:{acct}:secret:{env}-db-creds-*"},
                            {"Effect": "Allow", "Action": ["kms:Decrypt"], "Resource": f"arn:aws:kms:{REGION}:{acct}:key/{env}-key-uuid"},
                        ]
                    },
                }],
                "managed_policies": [],
                "has_wildcard_resource_access": False,
            },
        ))

        # ─── EKS Clusters ───
        for cluster_name in [f"{env}-main", f"{env}-{'qa' if env == 'dev' else 'cfprod'}"]:
            eks_role_arn = f"arn:aws:iam::{acct}:role/{cluster_name}-eks-role"
            node_role_arn = f"arn:aws:iam::{acct}:role/{cluster_name}-node-role"

            resources.append(Resource(
                arn=f"arn:aws:eks:{REGION}:{acct}:cluster/{cluster_name}",
                resource_type=ResourceType.EKS_CLUSTER,
                name=cluster_name,
                region=REGION,
                account_id=acct,
                properties={
                    "cluster_name": cluster_name,
                    "kubernetes_version": "1.29",
                    "cluster_role_arn": eks_role_arn,
                    "endpoint_public_access": env == "dev",
                    "endpoint_private_access": True,
                    "public_access_cidrs": ["0.0.0.0/0"] if env == "dev" else [],
                    "vpc_id": vpc_id,
                    "security_group_ids": [sg_app_id],
                },
            ))

            # EKS IAM roles
            resources.append(Resource(
                arn=eks_role_arn,
                resource_type=ResourceType.IAM_ROLE,
                name=f"{cluster_name}-eks-role",
                region="global",
                account_id=acct,
                properties={
                    "role_name": f"{cluster_name}-eks-role",
                    "trust_policy": {"Statement": [{"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}]},
                    "inline_policies": [], "managed_policies": [],
                },
            ))

            # Nodegroup
            resources.append(Resource(
                arn=f"arn:aws:eks:{REGION}:{acct}:nodegroup/{cluster_name}/workers/ng001",
                resource_type=ResourceType.EKS_NODEGROUP,
                name=f"{cluster_name}-workers",
                region=REGION,
                account_id=acct,
                properties={
                    "cluster_name": cluster_name,
                    "node_role_arn": node_role_arn,
                    "instance_types": ["m5.xlarge"],
                    "desired_size": 3,
                    "security_group_ids": [sg_app_id],
                },
            ))

            resources.append(Resource(
                arn=node_role_arn,
                resource_type=ResourceType.IAM_ROLE,
                name=f"{cluster_name}-node-role",
                region="global",
                account_id=acct,
                properties={
                    "role_name": f"{cluster_name}-node-role",
                    "trust_policy": {"Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]},
                    "inline_policies": [],
                    "managed_policies": [{"name": "AmazonEKSWorkerNodePolicy", "arn": "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"}],
                },
            ))

        # ─── RDS (writer + reader) ───
        for suffix, is_writer in [("writer", True), ("reader", False)]:
            resources.append(Resource(
                arn=f"arn:aws:rds:{REGION}:{acct}:db:{env}-postgres-{suffix}",
                resource_type=ResourceType.RDS_INSTANCE,
                name=f"{env}-postgres-{suffix}",
                region=REGION,
                account_id=acct,
                properties={
                    "engine": "aurora-postgresql",
                    "engine_version": "15.4",
                    "publicly_accessible": False,
                    "storage_encrypted": True,
                    "iam_database_auth_enabled": True,
                    "vpc_id": vpc_id,
                    "vpc_security_group_ids": [sg_db_id],
                    "is_cluster_writer": is_writer,
                },
            ))

        # ─── ElastiCache (Redis) ───
        resources.append(Resource(
            arn=f"arn:aws:elasticache:{REGION}:{acct}:replicationgroup:{env}-redis",
            resource_type=ResourceType.ELASTICACHE_CLUSTER,
            name=f"{env}-redis",
            region=REGION,
            account_id=acct,
            properties={
                "engine": "redis",
                "engine_version": "7.0",
                "at_rest_encryption": True,
                "transit_encryption": True,
                "auth_token_enabled": True,
                "vpc_id": vpc_id,
                "security_group_ids": [sg_db_id],
            },
        ))

        # ─── DynamoDB ───
        resources.append(Resource(
            arn=f"arn:aws:dynamodb:{REGION}:{acct}:table/{env}-users",
            resource_type=ResourceType.DYNAMODB_TABLE,
            name=f"{env}-users",
            region=REGION,
            account_id=acct,
            properties={
                "table_name": f"{env}-users",
                "billing_mode": "PAY_PER_REQUEST",
                "encryption_type": "KMS",
                "kms_key_arn": f"arn:aws:kms:{REGION}:{acct}:key/{env}-key-uuid",
                "table_display_name": f"{env}-users",
            },
        ))

        # ─── S3 Buckets ───
        for bucket_name, is_public in [(f"{env}-app-assets-{acct}", False), (f"{env}-logs-{acct}", False), (f"{env}-static-{acct}", True)]:
            resources.append(Resource(
                arn=f"arn:aws:s3:::{bucket_name}",
                resource_type=ResourceType.S3_BUCKET,
                name=bucket_name,
                region=REGION,
                account_id=acct,
                properties={
                    "is_encrypted": True,
                    "has_bucket_policy": True,
                    "public_access_block": {
                        "block_public_acls": not is_public,
                        "ignore_public_acls": not is_public,
                        "block_public_policy": not is_public,
                        "restrict_public_buckets": not is_public,
                    },
                },
            ))

        # ─── KMS Key ───
        resources.append(Resource(
            arn=f"arn:aws:kms:{REGION}:{acct}:key/{env}-key-uuid",
            resource_type=ResourceType.KMS_KEY,
            name=f"{env}-master-key",
            region=REGION,
            account_id=acct,
            properties={
                "key_id": f"{env}-key-uuid",
                "key_state": "Enabled",
                "key_manager": "CUSTOMER",
                "description": f"{env} encryption key",
            },
        ))

        # ─── Secrets Manager ───
        resources.append(Resource(
            arn=f"arn:aws:secretsmanager:{REGION}:{acct}:secret:{env}-db-creds",
            resource_type=ResourceType.SECRETS_MANAGER_SECRET,
            name=f"{env}-db-creds",
            region=REGION,
            account_id=acct,
            properties={
                "secret_name": f"{env}-db-creds",
                "kms_key_arn": f"arn:aws:kms:{REGION}:{acct}:key/{env}-key-uuid",
                "rotation_enabled": True,
            },
        ))

        # ─── WAF ───
        waf_arn = f"arn:aws:wafv2:{REGION}:{acct}:regional/webacl/{env}-waf/waf001"
        resources.append(Resource(
            arn=waf_arn,
            resource_type=ResourceType.WAF_WEB_ACL,
            name=f"{env}-waf",
            region=REGION,
            account_id=acct,
            properties={
                "web_acl_name": f"{env}-waf",
                "scope": "REGIONAL",
                "rule_count": 5,
                "default_action": "allow",
            },
        ))

        # ─── API Gateway ───
        apigw_arn = f"arn:aws:execute-api:{REGION}:{acct}:{env}-api"
        resources.append(Resource(
            arn=apigw_arn,
            resource_type=ResourceType.API_GATEWAY_REST_API,
            name=f"{env}-rest-api",
            region=REGION,
            account_id=acct,
            properties={
                "api_id": f"{env}-api",
                "name": f"{env}-rest-api",
                "endpoint_types": ["REGIONAL"],
                "is_private": False,
                "is_edge": False,
                "has_authorizers": True,
                "has_waf": True,
                "stage_waf_arns": [waf_arn],
                "stage_count": 1,
                "stage_summaries": [{"stage_name": env, "waf_arn": waf_arn, "cache_cluster_enabled": False, "tracing_enabled": True, "throttling_rate_limit": 1000}],
                "integration_targets": [
                    {"target_arn": lambda_arn, "type": "lambda", "method": "POST"},
                ],
            },
        ))

        # ─── CloudFront ───
        resources.append(Resource(
            arn=f"arn:aws:cloudfront::{acct}:distribution/{env}CF001",
            resource_type=ResourceType.CLOUDFRONT_DISTRIBUTION,
            name=f"{env}.example.com",
            region="global",
            account_id=acct,
            properties={
                "distribution_id": f"{env}CF001",
                "domain_name": f"{env}.example.com",
                "enabled": True,
                "has_waf": True,
                "web_acl_id": waf_arn,
                "https_only": True,
                "viewer_protocol_policy": "redirect-to-https",
                "origins": [
                    {"id": "alb-origin", "domain_name": alb_dns, "is_s3_origin": False, "oai": "", "custom_protocol": "https-only"},
                    {"id": "s3-static", "domain_name": f"{env}-static-{acct}.s3.{REGION}.amazonaws.com", "is_s3_origin": True, "oai": "OAI123", "custom_protocol": None},
                ],
                "origin_count": 2,
            },
        ))

        # ─── NAT Gateway ───
        resources.append(Resource(
            arn=f"arn:aws:ec2:{REGION}:{acct}:natgateway/nat-{env}001",
            resource_type=ResourceType.NAT_GATEWAY,
            name=f"{env}-nat",
            region=REGION,
            account_id=acct,
            properties={
                "nat_gateway_id": f"nat-{env}001",
                "state": "available",
                "connectivity_type": "public",
                "vpc_id": vpc_id,
                "subnet_id": f"subnet-{env}-public-1",
                "public_ips": ["52.66.1.1"],
            },
        ))

    return resources


def main():
    resources = _make_resources()

    scan_result = ScanResult(
        scan_id="mock-001",
        scanner_account_id=ACCOUNT_DEV,
        accounts_scanned=[ACCOUNT_DEV, ACCOUNT_PROD],
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
        regions_scanned=[REGION],
        resources=resources,
        errors=[],
    )

    builder = GraphBuilder(scan_result)
    graph = builder.build()

    print(f"Graph: {graph.number_of_nodes()} nodes, {graph.number_of_edges()} edges")

    output_path = Path("output/mock_graph.html")
    render_html(graph, output_path)
    print(f"Visualization saved to: {output_path.absolute()}")

    webbrowser.open(str(output_path.absolute()))


if __name__ == "__main__":
    main()
