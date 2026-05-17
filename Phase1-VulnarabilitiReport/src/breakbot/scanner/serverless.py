"""
Serverless orchestration scanner — EventBridge rules and Step Functions state machines.
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
        resources.extend(self._safe_scan_call(
            "events", "list_event_buses", region,
            lambda: self._scan_eventbridge(region),
        ))
        resources.extend(self._safe_scan_call(
            "stepfunctions", "list_state_machines", region,
            lambda: self._scan_step_functions(region),
        ))
        return resources

    # ──────────────────────── EventBridge ─────────────────────────────────

    def _scan_eventbridge(self, region: str) -> list[Resource]:
        events = self.session.client("events", region=region)
        resources: list[Resource] = []

        bus_names: list[str] = []
        resp = events.list_event_buses()
        for bus in resp.get("EventBuses", []):
            bus_names.append(bus["Name"])

        for bus_name in bus_names:
            try:
                paginator = events.get_paginator("list_rules")
                for page in paginator.paginate(EventBusName=bus_name):
                    for rule in page.get("Rules", []):
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
                        try:
                            resources.append(
                                self._normalize_rule(rule, bus_name, targets, region)
                            )
                        except Exception as e:
                            logger.warning(
                                "[serverless] failed to normalize rule %s: %s",
                                rule.get("Name", "?"), e,
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
            is_cross_acct = (
                t_arn.startswith("arn:aws")
                and f":{self.session.account_id}:" not in t_arn
                and "amazonaws.com" not in t_arn
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
            "state": rule.get("State"),
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
                except Exception as e:
                    logger.warning(
                        "[serverless] failed to normalize state machine %s: %s",
                        sm.get("name", "?"), e,
                    )

        return resources

    def _normalize_state_machine(self, sm: dict, region: str) -> Resource:
        arn = sm["stateMachineArn"]
        name = sm["name"]

        logging_config = sm.get("loggingConfiguration") or {}
        logging_level = logging_config.get("level", "OFF")

        tracing = sm.get("tracingConfiguration") or {}
        tracing_enabled = tracing.get("enabled", False)

        properties = {
            "state_machine_name": name,
            "type": sm.get("type"),
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
            tags={},
            properties=properties,
        )
