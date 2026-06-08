"""
Reusable construct: wraps an Athena SQL query + EventBridge schedule.

Usage:
    DetectionRule(
        self, "R040",
        sql_path="detection_rules/R-040_impossible_travel.sql",
        schedule=Schedule.rate(Duration.minutes(15)),
        severity="HIGH",
    )

Reads .sql file at synth time, creates:
  - Athena named query
  - EventBridge scheduled rule
  - Lambda that executes the query and emits findings
"""
# Phase 4 implementation — stub for now
