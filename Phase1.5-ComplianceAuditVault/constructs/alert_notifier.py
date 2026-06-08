"""
Reusable construct: routes findings to SNS → Slack/PagerDuty by severity.

Usage:
    AlertNotifier(
        self, "Notifier",
        sev1_target=pagerduty_topic,
        sev2_target=slack_topic,
        feedback_table=dynamo_table,  # for Real/False Alarm buttons
    )

sev1 → PagerDuty (immediate page)
sev2/sev3 → Slack with interactive buttons (Real / False Alarm)
Button responses stored in DynamoDB for tuning detection thresholds.
"""
# Phase 4 implementation — stub for now
