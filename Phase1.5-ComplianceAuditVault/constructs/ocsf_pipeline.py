"""
Reusable construct: Firehose + Lambda OCSF transformer per log source.

Usage:
    OcsfPipeline(self, "WAFPipeline", source="waf", transformer_code=waf_lambda)

Takes raw logs from a source (WAF, ALB, EKS, etc.),
transforms them to OCSF format via Lambda,
delivers to Security Lake S3 bucket as Parquet.
"""
# Phase 2-3 implementation — stub for now
