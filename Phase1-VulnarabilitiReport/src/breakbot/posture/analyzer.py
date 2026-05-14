"""
PostureAnalyzer — derives security findings from an existing ScanResult.

All checks are purely flag-based: no additional AWS API calls are made.
Every finding references the exact resource property that triggered it
so the LLM (and a human) can trace it back to the scanner output.

Checks are grouped by domain and ordered CRITICAL → HIGH → MEDIUM → LOW.
"""
from __future__ import annotations

from breakbot.models import ResourceType, ScanResult
from breakbot.models.resource import Resource
from breakbot.posture.findings import PostureFinding, Severity

# TCP ports that should never be open to 0.0.0.0/0.
# Maps port → (check_id, human label, severity)
_SG_PORT_CHECKS: dict[int, tuple[str, str, Severity]] = {
    22:    ("SG_OPEN_SSH",           "SSH (port 22)",           Severity.HIGH),
    23:    ("SG_OPEN_TELNET",        "Telnet (port 23)",        Severity.CRITICAL),
    3389:  ("SG_OPEN_RDP",           "RDP (port 3389)",         Severity.HIGH),
    3306:  ("SG_OPEN_MYSQL",         "MySQL (port 3306)",       Severity.HIGH),
    5432:  ("SG_OPEN_POSTGRES",      "PostgreSQL (port 5432)",  Severity.HIGH),
    27017: ("SG_OPEN_MONGODB",       "MongoDB (port 27017)",    Severity.HIGH),
    6379:  ("SG_OPEN_REDIS",         "Redis (port 6379)",       Severity.HIGH),
    1433:  ("SG_OPEN_MSSQL",         "MSSQL (port 1433)",       Severity.HIGH),
    5439:  ("SG_OPEN_REDSHIFT",      "Redshift (port 5439)",    Severity.HIGH),
    9200:  ("SG_OPEN_ELASTICSEARCH", "Elasticsearch (port 9200)", Severity.HIGH),
}

_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

# Lambda runtimes that have hit end-of-support as of 2026. AWS stops applying
# security patches after EOL — using these is a known-CVE risk.
_LAMBDA_EOL_RUNTIMES = frozenset({
    "python2.7", "python3.6", "python3.7", "python3.8", "python3.9",
    "nodejs10.x", "nodejs12.x", "nodejs14.x", "nodejs16.x",
    "ruby2.5", "ruby2.7", "ruby3.0",
    "dotnetcore2.1", "dotnetcore3.1", "dotnet5.0", "dotnet6",
    "go1.x",
    "java8",
})

# Substrings that suggest a parameter holds a credential regardless of its
# declared Type. SSM parameters that match these but are stored as plain
# String (not SecureString) are a finding.
_SECRET_NAME_PATTERNS = (
    "password", "secret", "token", "apikey", "api_key",
    "credential", "private", "passwd",
)


class PostureAnalyzer:
    """
    Usage:
        analyzer = PostureAnalyzer()
        findings = analyzer.analyze(result)   # list[PostureFinding], sorted CRITICAL-first
    """

    def analyze(self, result: ScanResult) -> list[PostureFinding]:
        findings: list[PostureFinding] = []
        seen: set[tuple[str, str]] = set()

        for resource in result.resources:
            for f in self._dispatch(resource):
                key = (f.check_id, f.resource_arn)
                if key not in seen:
                    seen.add(key)
                    findings.append(f)

        findings.sort(key=lambda f: (
            _SEVERITY_ORDER.index(f.severity.value),
            f.resource_arn,
        ))
        return findings

    # ─────────────────────────── Dispatcher ───────────────────────────────

    def _dispatch(self, resource: Resource) -> list[PostureFinding]:
        _HANDLERS = {
            ResourceType.SECURITY_GROUP:               self._check_sg,
            ResourceType.WAF_WEB_ACL:                  self._check_waf,
            ResourceType.S3_BUCKET:                    self._check_s3,
            ResourceType.RDS_INSTANCE:                 self._check_rds,
            ResourceType.DYNAMODB_TABLE:               self._check_dynamodb,
            ResourceType.ELASTICACHE_CLUSTER:          self._check_elasticache,
            ResourceType.SQS_QUEUE:                    self._check_sqs,
            ResourceType.SNS_TOPIC:                    self._check_sns,
            ResourceType.MSK_CLUSTER:                  self._check_msk,
            ResourceType.KINESIS_STREAM:               self._check_kinesis,
            ResourceType.KMS_KEY:                      self._check_kms,
            ResourceType.ECS_TASK_DEFINITION:          self._check_ecs_task_def,
            ResourceType.ECS_SERVICE:                  self._check_ecs_service,
            ResourceType.ECS_CLUSTER:                  self._check_ecs_cluster,
            ResourceType.EKS_CLUSTER:                  self._check_eks,
            ResourceType.IAM_USER:                     self._check_iam_user,
            ResourceType.IAM_ROLE:                     self._check_iam_role,
            ResourceType.LAMBDA_FUNCTION:              self._check_lambda,
            ResourceType.EC2_INSTANCE:                 self._check_ec2,
            ResourceType.SECRETS_MANAGER_SECRET:       self._check_secret,
            ResourceType.SSM_PARAMETER:                self._check_ssm_parameter,
            ResourceType.VPC:                          self._check_vpc,
            ResourceType.ALB:                          self._check_alb,
            ResourceType.COGNITO_USER_POOL:            self._check_cognito,
            ResourceType.API_GATEWAY_REST_API:         self._check_apigw_rest,
            ResourceType.API_GATEWAY_HTTP_API:         self._check_apigw_http,
            ResourceType.CLOUDFRONT_DISTRIBUTION:      self._check_cloudfront,
            ResourceType.STEP_FUNCTIONS_STATE_MACHINE: self._check_step_functions,
            ResourceType.EVENTBRIDGE_RULE:             self._check_eventbridge,
        }
        handler = _HANDLERS.get(resource.resource_type)
        return handler(resource) if handler else []

    # ─────────────────────────── Factory helper ───────────────────────────

    def _f(
        self,
        resource: Resource,
        check_id: str,
        severity: Severity,
        category: str,
        title: str,
        detail: str,
        remediation: str,
    ) -> PostureFinding:
        return PostureFinding(
            check_id=check_id,
            severity=severity,
            category=category,
            resource_arn=resource.arn,
            resource_type=resource.resource_type.value,
            resource_name=resource.name,
            region=resource.region,
            account_id=resource.account_id,
            title=title,
            detail=detail,
            remediation=remediation,
        )

    # ─────────────────────────── Network / Security Groups ────────────────

    def _check_sg(self, r: Resource) -> list[PostureFinding]:
        findings: list[PostureFinding] = []
        for rule in r.properties.get("ingress_rules", []):
            cidrs = rule.get("cidrs", []) + rule.get("ipv6_cidrs", [])
            is_internet = "0.0.0.0/0" in cidrs or "::/0" in cidrs
            if not is_internet:
                continue

            protocol = rule.get("protocol")
            from_port = rule.get("from_port")
            to_port = rule.get("to_port")

            if protocol == "-1":
                findings.append(self._f(
                    r,
                    "SG_OPEN_ALL_TRAFFIC",
                    Severity.CRITICAL,
                    "network",
                    "Security group allows all inbound traffic from the internet",
                    "protocol=-1 (all traffic), 0.0.0.0/0",
                    "Remove the all-traffic rule. Restrict to specific ports and source CIDRs.",
                ))
                continue  # all-traffic already subsumes every port check

            if protocol not in ("tcp", "6", "udp", "17"):
                continue
            if from_port is None or to_port is None:
                continue

            for port, (check_id, label, sev) in _SG_PORT_CHECKS.items():
                if from_port <= port <= to_port:
                    findings.append(self._f(
                        r,
                        check_id,
                        sev,
                        "network",
                        f"Security group allows {label} from the internet",
                        f"port {port}/{protocol} ingress open to 0.0.0.0/0",
                        f"Restrict port {port} to specific CIDRs or route access through a VPN/bastion.",
                    ))

        return findings

    # ─────────────────────────── WAF ──────────────────────────────────────

    def _check_waf(self, r: Resource) -> list[PostureFinding]:
        findings: list[PostureFinding] = []
        p = r.properties

        if p.get("default_action") == "Allow":
            findings.append(self._f(
                r,
                "WAF_ALLOW_MODE",
                Severity.HIGH,
                "waf",
                "WAF web ACL is in Allow mode (not blocking)",
                "default_action=Allow — WAF is observing but not blocking requests",
                "Change default_action to Block and add rules to allow legitimate traffic.",
            ))

        if p.get("rule_count", 0) == 0:
            findings.append(self._f(
                r,
                "WAF_NO_RULES",
                Severity.HIGH,
                "waf",
                "WAF web ACL has no rules",
                "rule_count=0 — the ACL is a placeholder with no protection",
                "Add managed rule groups (e.g., AWSManagedRulesCommonRuleSet) to the web ACL.",
            ))

        if not p.get("cloudwatch_metrics_enabled", True):
            findings.append(self._f(
                r,
                "WAF_NO_METRICS",
                Severity.MEDIUM,
                "waf",
                "WAF web ACL has CloudWatch metrics disabled",
                "cloudwatch_metrics_enabled=False — no visibility into blocked requests",
                "Enable CloudWatch metrics and sampled requests on the web ACL.",
            ))

        return findings

    # ─────────────────────────── S3 ───────────────────────────────────────

    def _check_s3(self, r: Resource) -> list[PostureFinding]:
        findings: list[PostureFinding] = []
        pab = r.properties.get("public_access_block") or {}

        # All four settings must be True for full protection
        missing = [k for k, v in pab.items() if not v]
        if missing or not pab:
            findings.append(self._f(
                r,
                "S3_PUBLIC_ACCESS_BLOCK_DISABLED",
                Severity.HIGH,
                "data",
                "S3 bucket public access block is not fully enabled",
                f"Disabled settings: {', '.join(missing) if missing else 'all settings absent'}",
                "Enable all four S3 Block Public Access settings on the bucket.",
            ))

        policy = r.properties.get("bucket_policy")
        if policy:
            for stmt in policy.get("Statement", []):
                if stmt.get("Effect") != "Allow":
                    continue
                principal = stmt.get("Principal", {})
                if principal == "*" or principal == {"AWS": "*"}:
                    findings.append(self._f(
                        r,
                        "S3_BUCKET_POLICY_PUBLIC",
                        Severity.CRITICAL,
                        "data",
                        "S3 bucket policy grants access to everyone",
                        "Policy has Allow statement with Principal: * (no conditions)",
                        "Remove the wildcard Principal or add a restrictive aws:SourceAccount condition.",
                    ))
                    break

        return findings

    # ─────────────────────────── RDS ──────────────────────────────────────

    def _check_rds(self, r: Resource) -> list[PostureFinding]:
        findings: list[PostureFinding] = []
        p = r.properties

        if p.get("publicly_accessible"):
            findings.append(self._f(
                r,
                "RDS_PUBLICLY_ACCESSIBLE",
                Severity.HIGH,
                "data",
                "RDS instance is publicly accessible",
                "publicly_accessible=True — the DB endpoint resolves to a public IP",
                "Disable public accessibility. Access the instance from within the VPC only.",
            ))

        if not p.get("storage_encrypted"):
            findings.append(self._f(
                r,
                "RDS_NOT_ENCRYPTED",
                Severity.HIGH,
                "encryption",
                "RDS instance storage is not encrypted at rest",
                "storage_encrypted=False",
                "Enable encryption at rest (requires snapshot + restore into a new encrypted instance).",
            ))

        return findings

    # ─────────────────────────── DynamoDB ─────────────────────────────────

    def _check_dynamodb(self, r: Resource) -> list[PostureFinding]:
        findings: list[PostureFinding] = []
        p = r.properties

        if not p.get("sse_enabled"):
            sse_type = p.get("sse_type") or "none"
            findings.append(self._f(
                r,
                "DYNAMODB_NOT_KMS_ENCRYPTED",
                Severity.MEDIUM,
                "encryption",
                "DynamoDB table is not encrypted with a KMS key",
                f"sse_type={sse_type}, sse_enabled=False",
                "Enable SSE with a customer-managed KMS key for regulatory compliance.",
            ))

        return findings

    # ─────────────────────────── ElastiCache ──────────────────────────────

    def _check_elasticache(self, r: Resource) -> list[PostureFinding]:
        findings: list[PostureFinding] = []
        p = r.properties

        if not p.get("at_rest_encryption_enabled"):
            findings.append(self._f(
                r,
                "ELASTICACHE_NO_AT_REST_ENCRYPTION",
                Severity.HIGH,
                "encryption",
                "ElastiCache cluster does not encrypt data at rest",
                "at_rest_encryption_enabled=False",
                "Enable encryption at rest. Requires creating a new cluster (cannot be enabled in-place).",
            ))

        if not p.get("transit_encryption_enabled"):
            findings.append(self._f(
                r,
                "ELASTICACHE_NO_TRANSIT_ENCRYPTION",
                Severity.HIGH,
                "encryption",
                "ElastiCache cluster does not encrypt data in transit",
                "transit_encryption_enabled=False",
                "Enable TLS in-transit encryption. Requires creating a new cluster.",
            ))

        return findings

    # ─────────────────────────── SQS ──────────────────────────────────────

    def _check_sqs(self, r: Resource) -> list[PostureFinding]:
        findings: list[PostureFinding] = []
        p = r.properties

        if p.get("is_public"):
            findings.append(self._f(
                r,
                "SQS_PUBLICLY_ACCESSIBLE",
                Severity.CRITICAL,
                "data",
                "SQS queue is publicly accessible via resource policy",
                "Queue policy has Allow statement with Principal: * (no conditions)",
                "Remove the wildcard Principal or restrict access with aws:SourceAccount conditions.",
            ))

        if not p.get("is_encrypted"):
            findings.append(self._f(
                r,
                "SQS_NOT_ENCRYPTED",
                Severity.MEDIUM,
                "encryption",
                "SQS queue is not encrypted with KMS",
                "KmsMasterKeyId not set — messages stored in plaintext",
                "Configure a KMS key for server-side encryption on the queue.",
            ))

        return findings

    # ─────────────────────────── SNS ──────────────────────────────────────

    def _check_sns(self, r: Resource) -> list[PostureFinding]:
        findings: list[PostureFinding] = []
        p = r.properties

        if p.get("is_public"):
            findings.append(self._f(
                r,
                "SNS_PUBLICLY_ACCESSIBLE",
                Severity.CRITICAL,
                "data",
                "SNS topic is publicly accessible via resource policy",
                "Topic policy has Allow statement with Principal: * (no conditions)",
                "Remove the wildcard Principal or restrict with aws:SourceAccount conditions.",
            ))

        if not p.get("is_encrypted"):
            findings.append(self._f(
                r,
                "SNS_NOT_ENCRYPTED",
                Severity.MEDIUM,
                "encryption",
                "SNS topic is not encrypted with KMS",
                "KmsMasterKeyId not set — message payloads stored in plaintext",
                "Configure a KMS key for server-side encryption on the topic.",
            ))

        return findings

    # ─────────────────────────── MSK ──────────────────────────────────────

    def _check_msk(self, r: Resource) -> list[PostureFinding]:
        findings: list[PostureFinding] = []
        p = r.properties

        client_broker = p.get("client_broker_encryption", "TLS")
        if client_broker in ("PLAINTEXT", "TLS_PLAINTEXT"):
            findings.append(self._f(
                r,
                "MSK_PLAINTEXT_IN_TRANSIT",
                Severity.HIGH,
                "encryption",
                "MSK cluster allows unencrypted client-to-broker connections",
                f"client_broker_encryption={client_broker}",
                "Set ClientBroker to TLS to enforce encryption for all client connections.",
            ))

        if p.get("unauthenticated_access_enabled"):
            findings.append(self._f(
                r,
                "MSK_UNAUTHENTICATED_ACCESS",
                Severity.HIGH,
                "identity",
                "MSK cluster allows unauthenticated access",
                "unauthenticated_access_enabled=True",
                "Disable unauthenticated access and require IAM SASL or mTLS authentication.",
            ))

        return findings

    # ─────────────────────────── Kinesis ──────────────────────────────────

    def _check_kinesis(self, r: Resource) -> list[PostureFinding]:
        findings: list[PostureFinding] = []
        if r.properties.get("encryption_type", "NONE") == "NONE":
            findings.append(self._f(
                r,
                "KINESIS_NOT_ENCRYPTED",
                Severity.MEDIUM,
                "encryption",
                "Kinesis stream is not encrypted at rest",
                "encryption_type=NONE — stream records stored in plaintext",
                "Enable server-side encryption with a KMS key on the stream.",
            ))
        return findings

    # ─────────────────────────── KMS ──────────────────────────────────────

    def _check_kms(self, r: Resource) -> list[PostureFinding]:
        findings: list[PostureFinding] = []
        p = r.properties

        # Only flag customer-managed symmetric AWS_KMS keys that are Enabled
        # and have rotation_enabled explicitly False (None means we couldn't check)
        if (
            p.get("key_manager") == "CUSTOMER"
            and p.get("key_spec") == "SYMMETRIC_DEFAULT"
            and p.get("key_state") == "Enabled"
            and p.get("rotation_enabled") is False
        ):
            findings.append(self._f(
                r,
                "KMS_KEY_ROTATION_DISABLED",
                Severity.MEDIUM,
                "encryption",
                "Customer-managed KMS key has automatic rotation disabled",
                "rotation_enabled=False — key material never rotates",
                "Enable automatic annual key rotation via KMS key settings.",
            ))

        return findings

    # ─────────────────────────── ECS ──────────────────────────────────────

    def _check_ecs_task_def(self, r: Resource) -> list[PostureFinding]:
        findings: list[PostureFinding] = []
        p = r.properties

        if p.get("has_privileged_container"):
            findings.append(self._f(
                r,
                "ECS_PRIVILEGED_CONTAINER",
                Severity.CRITICAL,
                "compute",
                "ECS task definition contains a privileged container",
                "has_privileged_container=True — near-full host access from within the container",
                "Remove privileged: true from all container definitions unless absolutely required.",
            ))

        if p.get("pid_mode") == "host":
            findings.append(self._f(
                r,
                "ECS_HOST_PID_NAMESPACE",
                Severity.CRITICAL,
                "compute",
                "ECS task definition shares the host PID namespace",
                "pid_mode=host — container can enumerate and signal all host processes",
                "Remove pid_mode=host. Use default (task-scoped) PID namespace.",
            ))

        if p.get("ipc_mode") == "host":
            findings.append(self._f(
                r,
                "ECS_HOST_IPC_NAMESPACE",
                Severity.HIGH,
                "compute",
                "ECS task definition shares the host IPC namespace",
                "ipc_mode=host — container can access shared memory on the host",
                "Remove ipc_mode=host. Use default (task-scoped) IPC namespace.",
            ))

        if not p.get("task_role_arn"):
            findings.append(self._f(
                r,
                "ECS_NO_TASK_ROLE",
                Severity.LOW,
                "identity",
                "ECS task definition has no task IAM role assigned",
                "task_role_arn not set",
                "If tasks need AWS API access, assign a least-privilege task role. "
                "Without one, tasks run with no AWS identity (application credentials must be injected).",
            ))

        return findings

    def _check_ecs_service(self, r: Resource) -> list[PostureFinding]:
        findings: list[PostureFinding] = []
        if r.properties.get("assign_public_ip"):
            findings.append(self._f(
                r,
                "ECS_SERVICE_PUBLIC_IP",
                Severity.MEDIUM,
                "network",
                "ECS service assigns public IPs to tasks",
                "assign_public_ip=ENABLED — tasks are directly reachable from the internet",
                "Place tasks behind a load balancer and set assignPublicIp to DISABLED.",
            ))
        return findings

    def _check_ecs_cluster(self, r: Resource) -> list[PostureFinding]:
        findings: list[PostureFinding] = []
        if not r.properties.get("container_insights_enabled"):
            findings.append(self._f(
                r,
                "ECS_CLUSTER_NO_INSIGHTS",
                Severity.LOW,
                "compute",
                "ECS cluster has Container Insights disabled",
                "container_insights_enabled=False — limited CloudWatch visibility",
                "Enable Container Insights on the cluster for task-level metrics and logging.",
            ))
        return findings

    # ─────────────────────────── EKS ──────────────────────────────────────

    def _check_eks(self, r: Resource) -> list[PostureFinding]:
        findings: list[PostureFinding] = []
        p = r.properties

        if p.get("endpoint_public_access", True):
            cidrs = p.get("public_access_cidrs") or ["0.0.0.0/0"]
            if "0.0.0.0/0" in cidrs:
                findings.append(self._f(
                    r,
                    "EKS_PUBLIC_API_ENDPOINT",
                    Severity.HIGH,
                    "network",
                    "EKS cluster API server endpoint is publicly accessible from any IP",
                    f"endpoint_public_access=True, public_access_cidrs={cidrs}",
                    "Restrict publicAccessCidrs to known CIDR ranges, or disable the public endpoint.",
                ))

        if not p.get("logging_enabled"):
            findings.append(self._f(
                r,
                "EKS_LOGGING_DISABLED",
                Severity.MEDIUM,
                "compute",
                "EKS cluster control plane logging is disabled",
                "logging_enabled=False — no API server, audit, or authenticator logs in CloudWatch",
                "Enable control plane logging (at minimum: audit and authenticator log types).",
            ))

        if not p.get("secrets_encrypted"):
            findings.append(self._f(
                r,
                "EKS_SECRETS_NOT_ENCRYPTED",
                Severity.HIGH,
                "encryption",
                "EKS cluster etcd secrets are not KMS-encrypted",
                "secrets_encrypted=False — Kubernetes Secrets stored in plaintext in etcd",
                "Add an encryption config with a KMS provider for the 'secrets' resource.",
            ))

        return findings

    # ─────────────────────────── IAM Users ────────────────────────────────

    def _check_iam_user(self, r: Resource) -> list[PostureFinding]:
        findings: list[PostureFinding] = []
        p = r.properties

        if p.get("has_active_access_keys"):
            findings.append(self._f(
                r,
                "IAM_USER_ACTIVE_ACCESS_KEYS",
                Severity.MEDIUM,
                "identity",
                "IAM user has active long-lived access keys",
                "has_active_access_keys=True — static credentials that can be leaked",
                "Replace with IAM role-based access. If keys are required, rotate regularly and enforce least privilege.",
            ))

        if not p.get("mfa_enabled"):
            findings.append(self._f(
                r,
                "IAM_USER_NO_MFA",
                Severity.HIGH,
                "identity",
                "IAM user has no MFA device configured",
                "mfa_enabled=False",
                "Enforce MFA for all IAM users. Consider an SCP requiring aws:MultiFactorAuthPresent.",
            ))

        return findings

    # ─────────────────────────── Cognito ──────────────────────────────────

    def _check_cognito(self, r: Resource) -> list[PostureFinding]:
        findings: list[PostureFinding] = []
        p = r.properties

        if p.get("mfa_configuration") == "OFF":
            findings.append(self._f(
                r,
                "COGNITO_MFA_OFF",
                Severity.HIGH,
                "identity",
                "Cognito user pool has MFA disabled",
                "mfa_configuration=OFF — users authenticate with password only",
                "Enable MFA (set to OPTIONAL first to avoid locking out existing users, then ON).",
            ))

        adv_sec = p.get("advanced_security_mode", "OFF")
        if adv_sec != "ENFORCED":
            findings.append(self._f(
                r,
                "COGNITO_ADVANCED_SECURITY_NOT_ENFORCED",
                Severity.MEDIUM,
                "identity",
                "Cognito user pool advanced security is not in enforced mode",
                f"advanced_security_mode={adv_sec} — no adaptive auth or compromised-credential blocking",
                "Set AdvancedSecurityMode to ENFORCED to block compromised credentials and suspicious sign-ins.",
            ))

        pwd_len = p.get("password_min_length", 8)
        if pwd_len < 12:
            findings.append(self._f(
                r,
                "COGNITO_WEAK_PASSWORD_POLICY",
                Severity.LOW,
                "identity",
                "Cognito user pool minimum password length is below 12 characters",
                f"password_min_length={pwd_len} (recommended: ≥12)",
                "Increase the minimum password length to at least 12 characters in the pool's password policy.",
            ))

        return findings

    # ─────────────────────── API Gateway REST API ──────────────────────────

    def _check_apigw_rest(self, r: Resource) -> list[PostureFinding]:
        findings: list[PostureFinding] = []
        p = r.properties

        if not p.get("has_waf") and not p.get("is_private"):
            findings.append(self._f(
                r,
                "APIGW_REST_NO_WAF",
                Severity.MEDIUM,
                "waf",
                "API Gateway REST API has no WAF on any stage",
                "has_waf=False — no WAFv2 web ACL attached to any stage",
                "Associate a WAFv2 web ACL with each internet-facing stage.",
            ))

        if p.get("stage_count", 0) == 0:
            findings.append(self._f(
                r,
                "APIGW_REST_NO_STAGES",
                Severity.LOW,
                "compute",
                "API Gateway REST API has no deployed stages",
                "stage_count=0 — API exists but is not deployed",
                "Deploy the API to a stage or delete it if unused.",
            ))

        return findings

    # ─────────────────────── API Gateway HTTP API ──────────────────────────

    def _check_apigw_http(self, r: Resource) -> list[PostureFinding]:
        findings: list[PostureFinding] = []
        p = r.properties

        if not p.get("has_authorizer"):
            findings.append(self._f(
                r,
                "APIGW_HTTP_NO_AUTHORIZER",
                Severity.HIGH,
                "identity",
                "API Gateway HTTP API has no authorizer configured",
                "has_authorizer=False — all routes are publicly accessible without authentication",
                "Add a JWT or Lambda authorizer, or restrict routes with IAM auth.",
            ))

        if p.get("cors_allows_all_origins"):
            findings.append(self._f(
                r,
                "APIGW_HTTP_CORS_WILDCARD",
                Severity.MEDIUM,
                "network",
                "API Gateway HTTP API allows CORS requests from any origin",
                "cors_allow_origins contains '*'",
                "Restrict AllowOrigins to the specific domains that need access.",
            ))

        return findings

    # ─────────────────────── CloudFront ───────────────────────────────────

    def _check_cloudfront(self, r: Resource) -> list[PostureFinding]:
        findings: list[PostureFinding] = []
        p = r.properties

        if not p.get("https_only"):
            findings.append(self._f(
                r,
                "CLOUDFRONT_HTTP_ALLOWED",
                Severity.MEDIUM,
                "network",
                "CloudFront distribution allows unencrypted HTTP connections",
                f"viewer_protocol_policy={p.get('viewer_protocol_policy', 'allow-all')}",
                "Set ViewerProtocolPolicy to redirect-to-https or https-only.",
            ))

        if not p.get("has_waf"):
            findings.append(self._f(
                r,
                "CLOUDFRONT_NO_WAF",
                Severity.MEDIUM,
                "waf",
                "CloudFront distribution has no WAF web ACL attached",
                "has_waf=False — no WAF protection on this distribution",
                "Associate a WAFv2 (CLOUDFRONT scope) web ACL with the distribution.",
            ))

        if p.get("s3_origins_without_oai"):
            origins = p.get("s3_origins_without_oai", [])
            findings.append(self._f(
                r,
                "CLOUDFRONT_S3_ORIGIN_NO_OAI",
                Severity.HIGH,
                "data",
                "CloudFront distribution has S3 origins without Origin Access Identity",
                f"S3 origins bypassed: {origins}",
                "Create an OAI or OAC and restrict the S3 bucket policy to only allow CloudFront.",
            ))

        if not p.get("has_logging"):
            findings.append(self._f(
                r,
                "CLOUDFRONT_NO_LOGGING",
                Severity.LOW,
                "compute",
                "CloudFront distribution has access logging disabled",
                "has_logging=False — no record of requests served by this distribution",
                "Enable access logging to an S3 bucket for audit and forensic purposes.",
            ))

        return findings

    # ─────────────────────── Step Functions ───────────────────────────────

    def _check_step_functions(self, r: Resource) -> list[PostureFinding]:
        findings: list[PostureFinding] = []
        p = r.properties

        if not p.get("logging_enabled"):
            findings.append(self._f(
                r,
                "SFN_LOGGING_DISABLED",
                Severity.MEDIUM,
                "compute",
                "Step Functions state machine has logging disabled",
                "logging_level=OFF — no execution history in CloudWatch Logs",
                "Enable logging (at minimum ERROR level) to a CloudWatch log group.",
            ))

        if not p.get("tracing_enabled"):
            findings.append(self._f(
                r,
                "SFN_TRACING_DISABLED",
                Severity.LOW,
                "compute",
                "Step Functions state machine has X-Ray tracing disabled",
                "tracing_enabled=False",
                "Enable X-Ray tracing to get distributed traces across state machine executions.",
            ))

        return findings

    # ─────────────────────────── IAM Roles ────────────────────────────────

    def _check_iam_role(self, r: Resource) -> list[PostureFinding]:
        """
        Trust policy + permission audits. Three high-value checks:
          1. Wildcard Principal in trust policy (anyone can assume)
          2. Cross-account trust without aws:ExternalId (confused-deputy)
          3. iam:PassRole with wildcard resource (privesc to any role)
        """
        findings: list[PostureFinding] = []
        trust = r.properties.get("trust_policy") or {}

        # (1) Wildcard trust
        for stmt in trust.get("Statement", []):
            if stmt.get("Effect") != "Allow":
                continue
            principal = stmt.get("Principal", {})
            is_wildcard = (
                principal == "*"
                or principal == {"AWS": "*"}
                or (isinstance(principal, dict) and principal.get("AWS") == "*")
            )
            if is_wildcard and not stmt.get("Condition"):
                findings.append(self._f(
                    r,
                    "IAM_ROLE_WILDCARD_TRUST",
                    Severity.CRITICAL,
                    "identity",
                    "IAM role trust policy allows any AWS principal to assume it",
                    "Principal: * (no Condition) — any AWS account can assume this role",
                    "Restrict the trust policy to specific account IDs / role ARNs, "
                    "or add an sts:ExternalId / aws:SourceArn condition.",
                ))
                break

        # (2) Cross-account trust without ExternalId
        for stmt in trust.get("Statement", []):
            if stmt.get("Effect") != "Allow":
                continue
            principal = stmt.get("Principal", {})
            if not isinstance(principal, dict):
                continue
            aws_p = principal.get("AWS")
            if isinstance(aws_p, str):
                aws_p = [aws_p]
            if not aws_p:
                continue

            is_cross_account = any(
                isinstance(p, str)
                and p.startswith("arn:aws:iam::")
                and f"::{r.account_id}:" not in p
                for p in aws_p
            )
            if not is_cross_account:
                continue

            condition = stmt.get("Condition") or {}
            cond_keys: set[str] = set()
            for cond_block in condition.values():
                if isinstance(cond_block, dict):
                    cond_keys.update(cond_block.keys())
            has_external_id = any(
                k.lower() == "sts:externalid" for k in cond_keys
            )

            if not has_external_id:
                findings.append(self._f(
                    r,
                    "IAM_ROLE_CROSS_ACCOUNT_NO_EXTERNAL_ID",
                    Severity.HIGH,
                    "identity",
                    "IAM role trusts a cross-account principal without ExternalId condition",
                    "Cross-account trust statement is missing sts:ExternalId — confused-deputy risk",
                    "Add Condition: { StringEquals: { 'sts:ExternalId': '<unique-secret>' } } "
                    "to the trust statement.",
                ))
                break

        # (3) Wildcard iam:PassRole across all policy documents
        all_policies = (
            (r.properties.get("inline_policies") or [])
            + (r.properties.get("managed_policies") or [])
        )
        for policy in all_policies:
            doc = policy.get("document") or {}
            for stmt in doc.get("Statement", []):
                if stmt.get("Effect") != "Allow":
                    continue
                actions = stmt.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]
                resources_list = stmt.get("Resource", [])
                if isinstance(resources_list, str):
                    resources_list = [resources_list]

                allows_pass_role = any(
                    a in ("iam:*", "iam:PassRole", "*") for a in actions
                )
                if allows_pass_role and "*" in resources_list:
                    findings.append(self._f(
                        r,
                        "IAM_ROLE_WILDCARD_PASS_ROLE",
                        Severity.HIGH,
                        "identity",
                        "IAM role grants iam:PassRole on a wildcard resource",
                        f"Policy '{policy.get('name', '?')}' allows iam:PassRole on '*' "
                        "— can attach any role to any service",
                        "Restrict iam:PassRole to specific role ARNs and add a "
                        "iam:PassedToService condition where possible.",
                    ))
                    return findings  # one is enough; stop scanning policies

        return findings

    # ─────────────────────────── Lambda ──────────────────────────────────

    def _check_lambda(self, r: Resource) -> list[PostureFinding]:
        findings: list[PostureFinding] = []
        runtime = r.properties.get("runtime")
        if runtime in _LAMBDA_EOL_RUNTIMES:
            findings.append(self._f(
                r,
                "LAMBDA_EOL_RUNTIME",
                Severity.HIGH,
                "compute",
                f"Lambda function uses EOL/deprecated runtime ({runtime})",
                f"runtime={runtime} — AWS no longer applies security patches",
                "Upgrade to a supported runtime (e.g., python3.12, nodejs20.x, java21). "
                "Use `aws lambda list-functions` to inventory all functions on EOL runtimes.",
            ))
        return findings

    # ─────────────────────────── EC2 ──────────────────────────────────────

    def _check_ec2(self, r: Resource) -> list[PostureFinding]:
        findings: list[PostureFinding] = []
        p = r.properties

        if p.get("imds_v1_allowed"):
            findings.append(self._f(
                r,
                "EC2_IMDSV1_ALLOWED",
                Severity.HIGH,
                "compute",
                "EC2 instance allows IMDSv1 (tokenless metadata access)",
                "imds_v1_allowed=True — SSRF on this instance can steal the "
                "instance-profile credentials with no auth challenge",
                "Set HttpTokens=required on the instance metadata options "
                "(modify-instance-metadata-options API) to enforce IMDSv2.",
            ))

        return findings

    # ─────────────────────── Secrets Manager ──────────────────────────────

    def _check_secret(self, r: Resource) -> list[PostureFinding]:
        findings: list[PostureFinding] = []
        if not r.properties.get("rotation_enabled"):
            findings.append(self._f(
                r,
                "SECRET_ROTATION_DISABLED",
                Severity.MEDIUM,
                "identity",
                "Secrets Manager secret has automatic rotation disabled",
                "rotation_enabled=False — credentials never rotate",
                "Configure rotation with a Lambda rotation function (or use the "
                "service-native option for RDS / DocumentDB / Redshift secrets).",
            ))
        return findings

    # ─────────────────────── SSM Parameter ────────────────────────────────

    def _check_ssm_parameter(self, r: Resource) -> list[PostureFinding]:
        findings: list[PostureFinding] = []
        p = r.properties
        name_lower = (p.get("parameter_name") or "").lower()
        is_secret_named = any(pat in name_lower for pat in _SECRET_NAME_PATTERNS)

        if is_secret_named and p.get("type") != "SecureString":
            findings.append(self._f(
                r,
                "SSM_PARAMETER_PLAINTEXT_SECRET",
                Severity.HIGH,
                "identity",
                "SSM parameter name suggests a secret but is stored as plaintext",
                f"type={p.get('type', '?')}, name matches secret-pattern: {p.get('parameter_name')}",
                "Convert to SecureString. SecureString parameters are KMS-encrypted at rest "
                "and access can be audited via CloudTrail.",
            ))
        return findings

    # ─────────────────────── VPC ──────────────────────────────────────────

    def _check_vpc(self, r: Resource) -> list[PostureFinding]:
        findings: list[PostureFinding] = []
        if r.properties.get("is_default") and r.properties.get("state") == "available":
            findings.append(self._f(
                r,
                "DEFAULT_VPC_AVAILABLE",
                Severity.LOW,
                "network",
                "Default VPC is still available in this region",
                "is_default=True — default VPC has open security group rules and "
                "an attached internet gateway",
                "If no workloads use it, delete the default VPC. Custom VPCs give "
                "explicit control over routing, NACLs, and ingress.",
            ))
        return findings

    # ─────────────────────── ALB ──────────────────────────────────────────

    def _check_alb(self, r: Resource) -> list[PostureFinding]:
        findings: list[PostureFinding] = []
        p = r.properties

        # NLBs don't use SGs so the missing-SG check only applies to ALBs
        if (
            p.get("is_internet_facing")
            and p.get("is_alb")
            and not p.get("security_group_ids")
        ):
            findings.append(self._f(
                r,
                "ALB_INTERNET_FACING_NO_SG",
                Severity.HIGH,
                "network",
                "Internet-facing ALB has no security groups attached",
                "is_internet_facing=True, security_group_ids=[]",
                "Attach a security group to the ALB to restrict ingress.",
            ))
        return findings

    # ─────────────────────── EventBridge ──────────────────────────────────

    def _check_eventbridge(self, r: Resource) -> list[PostureFinding]:
        findings: list[PostureFinding] = []
        p = r.properties

        if p.get("has_cross_account_targets"):
            targets = p.get("cross_account_targets", [])
            findings.append(self._f(
                r,
                "EVENTBRIDGE_CROSS_ACCOUNT_TARGET",
                Severity.HIGH,
                "identity",
                "EventBridge rule delivers events to a resource in another AWS account",
                f"Cross-account targets: {targets}",
                "Verify these cross-account deliveries are intentional. "
                "Restrict the event bus resource policy if needed.",
            ))

        return findings
