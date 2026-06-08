# PC-05 Compliance Audit Vault

HIPAA-grade immutable logging pipeline with AI-powered incident correlation.

## What This Does

```
Logs from all accounts
        |
        v
AWS Security Lake (normalize to OCSF)
        |
        v
WORM Vault S3 (Object Lock Compliance, 7-year retention)
        |
        v
Athena detection rules (13 SQL patterns, scheduled)
        |
      MATCH? → Lambda → Bedrock AI → writes incident narrative
                                   → Slack/PagerDuty alert
                                   → stored in vault forever
```

## Architecture

```
stacks/                    One CDK stack per deployment phase
constructs/                Reusable building blocks (WormBucket, DetectionRule, etc.)
lambdas/                   Runtime code for Lambda functions
detection_rules/           SQL files — first-class, readable by security engineers
tests/                     CDK assertions + integration tests against real AWS
config/                    Per-environment values (dev=1 day, prod=7 years)
```

## Build Order

| Phase | Stack | What It Deploys |
|-------|-------|-----------------|
| 0 | VaultAccountStack | S3 + KMS + Object Lock + deny policies |
| 1 | SecurityLakeStack | Security Lake + native sources (CloudTrail, VPC) |
| 2-3 | CustomSourcesStack | Firehose + OCSF transformers (WAF, ALB, EKS, app) |
| 4 | DetectionsStack | Athena rules + EventBridge schedules + AI correlation |
| 5 | RemediationStack | Auto-remediation Lambdas (5 narrow patterns) |
| 6 | IntegrityStack | SHA-256 hash chain + monthly partition inventory |

## Quick Start

```bash
# Install deps
pip install -r requirements.txt

# Synthesize (no AWS needed — just generates CloudFormation)
cdk synth VaultAccountStack -c env=dev

# Deploy Phase 0 to sandbox
cdk deploy VaultAccountStack -c env=dev

# Validate immutability
bash scripts/validate-worm.sh audit-vault-dev
```

## Testing

```bash
pip install -r requirements-dev.txt
pytest tests/unit/ -v
```

## Key Design Decisions

- **CDK Python** over Terraform/CloudFormation — 100% AWS, cutting-edge services, testable
- **Object Lock COMPLIANCE** not GOVERNANCE — cannot be overridden even by root
- **Numbered stacks** — enforce deploy order, clear dependencies
- **SQL as first-class files** — security engineers review rules without touching infra code
- **constructs/** — one change to WormBucket fixes every stack that uses it

## Compliance Mapping (PC-05)

| Requirement | Evidence |
|------------|----------|
| Immutable retention (7 years) | Object Lock Compliance + deny-shorten policy |
| Encryption at rest | KMS CMK with auto-rotation |
| Tamper detection | SHA-256 hash chain (Phase 6) |
| Audit trail of access | S3 access logging + CloudTrail |
| Centralized collection | Security Lake OCSF normalization |
| Anomaly detection | 13 Athena detection rules |
| Incident documentation | AI correlation agent narratives |
