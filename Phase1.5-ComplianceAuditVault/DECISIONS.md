# Architecture Decision Records

## ADR-001: CDK Python over Terraform / CloudFormation

**Date:** 2026-06-09
**Decision:** AWS CDK (Python)
**Reason:** This project is 100% AWS-native (Security Lake, Bedrock, Object Lock, EventBridge). CDK stays current with cutting-edge AWS APIs where Terraform lags. Python matches Phase 1 codebase. CDK assertions enable unit testing infrastructure before deploy.

---

## ADR-002: Object Lock COMPLIANCE mode, not GOVERNANCE

**Date:** 2026-06-09
**Decision:** S3 Object Lock in COMPLIANCE mode
**Reason:** HIPAA 164.530(j) requires tamper-proof retention. GOVERNANCE mode can be overridden by privileged users with `s3:BypassGovernanceRetention`. COMPLIANCE mode cannot be shortened or removed by anyone — not root, not AWS support — until retention expires. Non-negotiable for audit trail integrity.

---

## ADR-003: Dedicated vault account outside blast radius

**Date:** 2026-06-09
**Decision:** Separate AWS account for immutable evidence storage
**Reason:** If prod account is compromised, attacker has full IAM. Logs in same account are vulnerable despite Object Lock (they could still fill quotas, disrupt access). Cross-account replication into isolated vault account with its own Object Lock ensures evidence survives total compromise of source account.

---

## ADR-004: Detection rules as standalone SQL files

**Date:** 2026-06-09
**Decision:** Each detection rule is a `.sql` file in `detection_rules/`, not embedded in Python
**Reason:** Security engineers (non-developers) must be able to read, review, and propose changes to detection logic without understanding CDK or Python. SQL is the lingua franca of security teams. The `detection_rule.py` construct wraps each file into EventBridge + Athena at deploy time.

---

## ADR-005: AI correlation is reactive, not proactive

**Date:** 2026-06-09
**Decision:** Bedrock agent fires ONLY on detection rule match, not continuous monitoring
**Reason:** Continuous AI monitoring of logs would be (a) prohibitively expensive at scale, (b) prone to noise/hallucination with no anchor event, (c) not what the spec requires. The AI's job: receive a specific finding → pull 30-min context window → explain what happened → store narrative. It's an automated investigator, not a chatbot or continuous watcher.

---

## ADR-006: Skip OpenSearch for PoC

**Date:** 2026-06-09
**Decision:** No OpenSearch in initial implementation
**Reason:** OpenSearch adds $100-300/month, requires cluster management, and duplicates what Athena already provides. The only advantage is sub-second search during live incidents. Athena handles all PoC use cases (detection rules, forensics, AI context window). Add OpenSearch later if SOC team needs real-time dashboards.

---

## ADR-007: Feedback loop on AI alerts (our addition)

**Date:** 2026-06-09
**Decision:** Slack messages include Real/False Alarm buttons
**Reason:** AI correlation agent will produce false positives. Without feedback, you never improve. Buttons feed back into a DynamoDB table, enabling: (a) tuning detection rule thresholds, (b) measuring AI accuracy over time, (c) demonstrating to auditors that the system self-improves. Not in manager's spec — our value-add.

---

## ADR-008: Weekly compliance digest (our addition)

**Date:** 2026-06-09
**Decision:** Dedicated `compliance_digest_stack.py` — weekly Bedrock summary → #compliance-digest Slack channel
**Reason:** Auditors ask "what happened this week?" Having a pre-built weekly summary (findings count, severity breakdown, AI narratives generated, false-positive rate) means the system self-documents. Reduces audit prep from days to minutes. Not in manager's spec — our value-add for audit readiness (Phase 7).
