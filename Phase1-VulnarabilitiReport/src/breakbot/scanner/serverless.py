"""
Serverless orchestration scanner — EventBridge rules and Step Functions state machines.

Key attack-path properties:
  EventBridge rule:
    - targets with cross-account ARNs  → data can flow to external accounts
    - targets with role_arn set         → EventBridge assumes that role to deliver events
    - schedule_expression set           → scheduled invocation (attacker-visible timing)

  Step Functions state machine:
    - role_arn                          → IAM role with all permissions the workflow needs;
                                          a compromised state machine = this role stolen
    - logging_level = OFF               → no execution history in CloudWatch
    - type = EXPRESS                    → high-throughput, async; logs go to CW only if configured
    - tracing_enabled = False           → no X-Ray traces for debugging attack paths

ARN formats:
  EventBridge rule: arn:aws:events:{region}:{account_id}:rule/{bus_name}/{rule_name}
  Step Functions:   arn:aws:states:{region}:{account_id}:stateMachine:{name}
"""
from __future__ import annotations

import logging

from botocore.exceptions import ClientError

from breakbot.models import Resource, ResourceType
from breakbot.scanner.base import BaseScanner

logger = logging.getLogger(__name__)


class ServerlessScanner(BaseScanner):
    domain = "serverless"

    def _scan_region(self, region: str) -> list[Resource]:
        resources: list[Resource] = []
        resources.extend(self._scan_eventbridge(region))
        resources.extend(self._scan_step_functions(region))
        return resources

    # ──────────────────────── EventBridge ─────────────────────────────────

    def _scan_eventbridge(self, region: str) -> list[Resource]:
        events = self.session.client("events", region=region)
        resources: list[Resource] = []

        # Collect all event buses (default + custom)
        bus_names: list[str] = []
        try:
            paginator = events.get_paginator("list_event_buses")
            for page in paginator.paginate():
                for bus in page.get("EventBuses", []):
                    bus_names.append(bus["Name"])
        except ClientError as e:
            logger.warning(
                "EventBridge ListEventBuses failed in %s: %s",
                region, e.response["Error"]["Code"],
            )
            return resources

        for bus_name in bus_names:
            try:
                paginator = events.get_paginator("list_rules")
                for page in paginator.paginate(EventBusName=bus_name):
                    for rule in page.get("Rules", []):
                        # Fetch targets for this rule
                        targets: list[dict] = []
                        try:
                            t_resp = events.list_targets_by_rule(
                                Rule=rule["Name"], EventBusName=bus_name
                            )
                            targets = t_resp.get("Targets", [])
                        except ClientError as e:
                            logger.warning(
                                "ListTargetsByRule %s failed: %s",
                                rule["Name"], e.response["Error"]["Code"],
                            )
                        resources.append(
                            self._normalize_rule(rule, bus_name, targets, region)
                        )
            except ClientError as e:
                logger.warning(
                    "EventBridge ListRules %s failed in %s: %s",
                    bus_name, region, e.response["Error"]["Code"],
                )

        return resources

    def _normalize_rule(
        self, rule: dict, bus_name: str, targets: list[dict], region: str
    ) -> Resource:
        rule_name = rule["Name"]
        arn = rule.get(
            "Arn",
            f"arn:aws:events:{region}:{self.session.account_id}:rule/{bus_name}/{rule_name}",
        )

        target_summaries = []
        cross_account_targets: list[str] = []
        role_arns_used: list[str] = []

        for t in targets:
            t_arn = t.get("Arn", "")
            t_role = t.get("RoleArn", "")
            # Cross-account = target ARN is in a different account
            is_cross_acct = (
                t_arn.startswith("arn:aws")
                and f":{self.session.account_id}:" not in t_arn
                and "amazonaws.com" not in t_arn  # exclude AWS service endpoints
            )
            if is_cross_acct:
                cross_account_targets.append(t_arn)
            if t_role:
                role_arns_used.append(t_role)

            target_summaries.append({
                "id": t.get("Id"),
                "arn": t_arn,
                "role_arn": t_role,
                "is_cross_account": is_cross_acct,
            })

        properties = {
            "rule_name": rule_name,
            "event_bus_name": bus_name,
            "state": rule.get("State"),              # ENABLED or DISABLED
            "schedule_expression": rule.get("ScheduleExpression"),
            "is_scheduled": bool(rule.get("ScheduleExpression")),
            "event_pattern": rule.get("EventPattern"),
            "description": rule.get("Description", ""),
            "target_count": len(targets),
            "targets": target_summaries,
            "cross_account_targets": cross_account_targets,
            "has_cross_account_targets": bool(cross_account_targets),
            "role_arns_used": role_arns_used,
        }

        return Resource(
            arn=arn,
            resource_type=ResourceType.EVENTBRIDGE_RULE,
            name=rule_name,
            region=region,
            account_id=self.session.account_id,
            properties=properties,
        )

    # ──────────────────── Step Functions ──────────────────────────────────

    def _scan_step_functions(self, region: str) -> list[Resource]:
        sfn = self.session.client("stepfunctions", region=region)
        resources: list[Resource] = []

        try:
            paginator = sfn.get_paginator("list_state_machines")
            for page in paginator.paginate():
                for sm in page.get("stateMachines", []):
                    try:
                        detail = sfn.describe_state_machine(
                            stateMachineArn=sm["stateMachineArn"]
                        )
                        resources.append(self._normalize_state_machine(detail, region))
                    except ClientError as e:
                        logger.warning(
                            "DescribeStateMachine %s failed: %s",
                            sm["name"], e.response["Error"]["Code"],
                        )
        except ClientError as e:
            logger.warning(
                "Step Functions ListStateMachines failed in %s: %s",
                region, e.response["Error"]["Code"],
            )

        return resources

    def _normalize_state_machine(self, sm: dict, region: str) -> Resource:
        arn = sm["stateMachineArn"]
        name = sm["name"]

        logging_config = sm.get("loggingConfiguration") or {}
        logging_level = logging_config.get("level", "OFF")

        tracing = sm.get("tracingConfiguration") or {}
        tracing_enabled = tracing.get("enabled", False)

        tags: dict[str, str] = {}
        try:
            # tags are not in describe_state_machine response, skip for now
            pass
        except Exception:
            pass

        properties = {
            "state_machine_name": name,
            "type": sm.get("type"),           # STANDARD or EXPRESS
            "status": sm.get("status"),
            "role_arn": sm.get("roleArn"),
            "logging_level": logging_level,
            "logging_enabled": logging_level != "OFF",
            "tracing_enabled": tracing_enabled,
            "definition_size": len(sm.get("definition", "")),
        }

        return Resource(
            arn=arn,
            resource_type=ResourceType.STEP_FUNCTIONS_STATE_MACHINE,
            name=name,
            region=region,
            account_id=self.session.account_id,
            tags=tags,
            properties=properties,
        )
