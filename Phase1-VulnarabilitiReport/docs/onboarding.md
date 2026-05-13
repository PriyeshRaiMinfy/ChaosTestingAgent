# BreakBot Onboarding

Two deployment models. Pick the one that matches your account setup.

| Model | Use when |
|---|---|
| **A. Single account** (skip to [§ Single account](#single-account-quickstart)) | You have one AWS account holding all envs (dev/qa/prod), you're a solo developer, or you're evaluating BreakBot before rolling it out. |
| **B. Multi-account Organization** (the rest of this doc) | You have a Control Tower landing zone or any AWS Organization with separate accounts for prod, dev, audit, etc. This is the production-grade setup. |

---

## Single account quickstart

For a developer or small team running everything in one AWS account.
No StackSet, no Organizations API, no cross-account roles needed.

### 1. Have credentials available

Any of these work — BreakBot picks them up automatically when you omit
`--profile`:

- `aws configure` set up a default profile in `~/.aws/credentials`
- `aws sso login` (IAM Identity Center)
- Environment variables `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY`
- Running inside AWS CloudShell (credentials are auto-attached)
- Running on EC2 / ECS with an instance profile / task role

### 2. Use a read-only IAM principal

The principal you run BreakBot as needs `ReadOnlyAccess` (or a tighter
policy with `*:Describe*`, `*:List*`, `*:Get*`, `iam:GetPolicyVersion`,
`cloudtrail:LookupEvents`). It must NOT have write permissions — BreakBot
refuses to scan if it detects write access during validation.

### 3. Install and run

```bash
pip install breakbot

# Verify the credentials are read-only
breakbot validate

# With a named profile:
breakbot validate --profile my-dev

# Full scan of one account, single region
breakbot scan --region us-east-1

# Full scan, every enabled region
breakbot scan --all-regions

# Restrict to one domain (fast, useful while iterating)
breakbot scan --domain identity

# Build the dependency graph
breakbot graph scans/scan-* --html graph.html --serialize attack_surface.txt
```

That's the entire single-account flow. Nothing else to set up.

---

## Multi-account Organization

This guide is for the security engineer setting up BreakBot in an AWS
Organization for the first time. It assumes you have admin access to the
Audit (or Security) account and StackSet deployment rights from the
Management account.

End state after this guide:

- A `BreakBotScannerRole` in your Audit account that is the identity
  BreakBot runs as.
- A `BreakBotReadOnly` role in every member account (deployed via
  CloudFormation StackSet) that grants `ReadOnlyAccess` plus the IAM
  policy-inspection and CloudTrail lookup permissions BreakBot needs.
- Your first cross-account scan output, written to S3 in the Audit
  account.

---

## 1. Decide where BreakBot will run

| Option | When to use |
|---|---|
| **AWS CloudShell in the Audit account** | First scans, ad-hoc investigations. Zero infra to provision. |
| **EC2 instance in the Audit account** | Persistent host, you want to schedule scans via cron. |
| **ECS Fargate scheduled task** | Production. Pay-per-run, no idle compute, EventBridge triggers it on a schedule. |
| **Local laptop with SSO credentials** | Developer work, debugging the tool itself. |

For first onboarding, use **CloudShell**. You can graduate to Fargate later.

---

## 2. Deploy the scanner role in the Audit account

In the Audit account, deploy `cloudformation/breakbot-scanner-role.yaml`.

```bash
# From CloudShell in the Audit account
aws cloudformation deploy \
  --stack-name BreakBotScannerRole \
  --template-file cloudformation/breakbot-scanner-role.yaml \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
      AllowedAssumers="arn:aws:iam::AUDIT_ACCOUNT_ID:role/AWSReservedSSO_AdminAccess_xxx" \
      EnableEc2InstanceProfile=false
```

Replace `AllowedAssumers` with whichever principal will run BreakBot from
CloudShell (your SSO role) or set `EnableEc2InstanceProfile=true` if you
plan to attach it to an EC2 instance.

Grab the output:

```bash
aws cloudformation describe-stacks \
  --stack-name BreakBotScannerRole \
  --query 'Stacks[0].Outputs[?OutputKey==`ScannerRoleArn`].OutputValue' \
  --output text
# arn:aws:iam::AUDIT_ACCOUNT_ID:role/BreakBotScannerRole
```

Keep that ARN. You will pass it into the next step.

---

## 3. Deploy `BreakBotReadOnly` to every member account via StackSet

From the **Management account** (StackSets only work from the Org
management account or a delegated admin), deploy the role to every
member account.

```bash
# Enable trusted access for StackSets, if not already done
aws organizations enable-aws-service-access \
  --service-principal stacksets.cloudformation.amazonaws.com

# Create the StackSet
aws cloudformation create-stack-set \
  --stack-set-name BreakBotReadOnly \
  --template-body file://cloudformation/breakbot-readonly-role.yaml \
  --permission-model SERVICE_MANAGED \
  --auto-deployment Enabled=true,RetainStacksOnAccountRemoval=false \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameters \
      ParameterKey=TrustedScannerPrincipalArn,ParameterValue=arn:aws:iam::AUDIT_ACCOUNT_ID:role/BreakBotScannerRole \
      ParameterKey=RoleName,ParameterValue=BreakBotReadOnly

# Roll it out to every account under the root OU
ROOT_ID=$(aws organizations list-roots --query 'Roots[0].Id' --output text)

aws cloudformation create-stack-instances \
  --stack-set-name BreakBotReadOnly \
  --deployment-targets OrganizationalUnitIds=$ROOT_ID \
  --regions us-east-1
```

Wait until the operation completes:

```bash
aws cloudformation list-stack-instances \
  --stack-set-name BreakBotReadOnly \
  --query 'Summaries[].Status'
```

When every entry says `CURRENT`, the role exists in every member account.

---

## 4. Install BreakBot in CloudShell

In CloudShell in the **Audit account**:

```bash
pip install breakbot
# or, while developing:
git clone https://github.com/your-org/breakbot && cd breakbot && pip install -e .
```

Verify the install:

```bash
breakbot --help
```

---

## 5. Validate the deployment

Before running a full scan, confirm BreakBot can reach every account
read-only:

```bash
# Assume the scanner role first if you're using SSO/IAM Identity Center
aws sts assume-role \
  --role-arn arn:aws:iam::AUDIT_ACCOUNT_ID:role/BreakBotScannerRole \
  --role-session-name breakbot-onboarding > /tmp/creds.json

# Export the temp creds into the shell
export AWS_ACCESS_KEY_ID=$(jq -r .Credentials.AccessKeyId  /tmp/creds.json)
export AWS_SECRET_ACCESS_KEY=$(jq -r .Credentials.SecretAccessKey /tmp/creds.json)
export AWS_SESSION_TOKEN=$(jq -r .Credentials.SessionToken /tmp/creds.json)

# Now validate
breakbot validate --org
```

Expected output, one block per member account:

```
123456789012 Production
  ✔ 123456789012: read access works
  ✔ 123456789012: write correctly denied
444455556666 Staging
  ✔ 444455556666: read access works
  ✔ 444455556666: write correctly denied
...

Validated: 7
Unreachable (role not deployed): 0
```

If you see `Unreachable`, the StackSet rollout did not complete for that
account. Re-run step 3.

If you see `Failed (write access detected...)`, something granted write
permissions to the role. Inspect the role's attached policies in that
account before running any scan.

---

## 6. First org-wide scan

```bash
breakbot scan --org --all-regions --output ./scans
```

Output:

```
scans/scan-YYYYMMDD-HHMMSS-xxxxxx/
├── scan.json                 ← merged, multi-account
├── ec2_instance.json
├── lambda_function.json
├── s3_bucket.json
├── iam_role.json
└── ...
```

Build the graph and produce the LLM-ready attack surface:

```bash
breakbot graph ./scans/scan-YYYYMMDD-HHMMSS-xxxxxx \
  --html graph.html \
  --serialize attack_surface.txt
```

Open `graph.html` in a browser. Cross-account edges are highlighted.

---

## 7. Schedule it (optional, Fargate)

For production, swap CloudShell for ECS Fargate triggered by EventBridge:

```
EventBridge rule (rate(1 day))
  ─► ECS Fargate task definition (BreakBot container)
       Task role: BreakBotScannerRole
       On finish: copy scan output to S3 in Audit account
       On finish: post summary to Slack via webhook
```

The Fargate task definition uses the same `BreakBotScannerRole` role.
The container image is `breakbot:latest` with command
`breakbot scan --org --all-regions --output /tmp/scans`.

---

## Troubleshooting

**`AccessDenied` on `organizations:ListAccounts`.** The scanner role is
not in the Management account and has not been registered as a delegated
administrator. Either run BreakBot from the Management account, or run
`aws organizations register-delegated-administrator` to delegate to the
Audit account.

**`AccessDenied` on `sts:AssumeRole` for a specific member account.** The
StackSet rollout did not complete for that account. Check the StackSet
operation status. If the account is suspended, it cannot receive the role.

**Sessions expire mid-scan.** Default assume-role duration is 1 hour. For
very large orgs (50+ accounts × 15 regions), raise
`MaxSessionDurationSeconds` in the StackSet parameters to 7200 or higher.

**Scan finds zero IAM resources but other domains work.** The
ReadOnlyAccess managed policy was recently changed and a specific Get/List
permission was removed. The `BreakBotIamInspection` inline policy in the
StackSet template is your backstop, but if it was deleted, redeploy.
