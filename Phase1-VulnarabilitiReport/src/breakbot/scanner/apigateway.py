"""
API Gateway scanner — REST APIs (v1) and HTTP/WebSocket APIs (v2).
"""
from __future__ import annotations

import logging

from botocore.exceptions import ClientError

from breakbot.models import Resource, ResourceType
from breakbot.scanner.base import BaseScanner

logger = logging.getLogger(__name__)


class ApiGatewayScanner(BaseScanner):
    domain = "apigateway"

    def _scan_region(self, region: str) -> list[Resource]:
        resources: list[Resource] = []
        resources.extend(self._safe_scan_call(
            "apigateway", "get_rest_apis", region,
            lambda: self._scan_rest_apis(region),
        ))
        resources.extend(self._safe_scan_call(
            "apigatewayv2", "get_apis", region,
            lambda: self._scan_http_apis(region),
        ))
        return resources

    # ─────────────────────── REST APIs (v1) ───────────────────────────────

    def _scan_rest_apis(self, region: str) -> list[Resource]:
        apigw = self.session.client("apigateway", region=region)
        resources: list[Resource] = []
        items: list[dict] = []

        paginator = apigw.get_paginator("get_rest_apis")
        for page in paginator.paginate():
            items.extend(page.get("items", []))

        for api in items:
            api_id = api["id"]
            stages: list[dict] = []
            try:
                stage_resp = apigw.get_stages(restApiId=api_id)
                stages = stage_resp.get("item", [])
            except ClientError as e:
                logger.warning(
                    "GetStages %s failed: %s", api_id, e.response["Error"]["Code"]
                )

            try:
                resources.append(self._normalize_rest_api(api, stages, region))
            except Exception as e:
                logger.warning(
                    "[apigateway] failed to normalize REST API %s: %s", api_id, e,
                )

        return resources

    def _normalize_rest_api(
        self, api: dict, stages: list[dict], region: str
    ) -> Resource:
        api_id = api["id"]
        arn = f"arn:aws:execute-api:{region}:{self.session.account_id}:{api_id}"

        endpoint_types = [
            c["types"][0]
            for c in api.get("endpointConfiguration", {}).get("types", []) or []
        ] or (api.get("endpointConfiguration", {}).get("types") or [])

        stage_summaries = []
        stage_waf_arns: list[str] = []
        for s in stages:
            waf_arn = s.get("webAclArn") or ""
            if waf_arn:
                stage_waf_arns.append(waf_arn)
            stage_summaries.append({
                "stage_name": s.get("stageName"),
                "waf_arn": waf_arn,
                "cache_cluster_enabled": s.get("cacheClusterEnabled", False),
                "tracing_enabled": s.get("tracingEnabled", False),
                "throttling_rate_limit": (
                    s.get("defaultRouteSettings", {}).get("throttlingRateLimit") or
                    s.get("methodSettings", {}).get("*/*", {}).get("throttlingRateLimit")
                ),
            })

        tags = api.get("tags", {}) or {}

        properties = {
            "api_id": api_id,
            "name": api.get("name"),
            "description": api.get("description", ""),
            "api_version": api.get("version"),
            "endpoint_types": endpoint_types,
            "is_private": "PRIVATE" in endpoint_types,
            "is_edge": "EDGE" in endpoint_types,
            "minimum_compression_size": api.get("minimumCompressionSize"),
            "api_key_source": api.get("apiKeySource"),
            "stage_count": len(stages),
            "stage_summaries": stage_summaries,
            "stage_waf_arns": stage_waf_arns,
            "has_waf": bool(stage_waf_arns),
            "has_authorizers": bool(api.get("disableExecuteApiEndpoint") is False),
        }

        return Resource(
            arn=arn,
            resource_type=ResourceType.API_GATEWAY_REST_API,
            name=api.get("name", api_id),
            region=region,
            account_id=self.session.account_id,
            tags=tags,
            properties=properties,
        )

    # ─────────────────────── HTTP / WebSocket APIs (v2) ────────────────────

    def _scan_http_apis(self, region: str) -> list[Resource]:
        apigwv2 = self.session.client("apigatewayv2", region=region)
        resources: list[Resource] = []

        paginator = apigwv2.get_paginator("get_apis")
        for page in paginator.paginate():
            for api in page.get("Items", []):
                authorizers: list[dict] = []
                try:
                    auth_resp = apigwv2.get_authorizers(ApiId=api["ApiId"])
                    authorizers = auth_resp.get("Items", [])
                except ClientError:
                    pass

                try:
                    resources.append(self._normalize_http_api(api, authorizers, region))
                except Exception as e:
                    logger.warning(
                        "[apigateway] failed to normalize HTTP API %s: %s",
                        api.get("ApiId", "?"), e,
                    )

        return resources

    def _normalize_http_api(
        self, api: dict, authorizers: list[dict], region: str
    ) -> Resource:
        api_id = api["ApiId"]
        arn = f"arn:aws:apigateway:{region}::/apis/{api_id}"

        cors = api.get("CorsConfiguration") or {}
        cors_allow_origins = cors.get("AllowOrigins") or []

        authorizer_types = [a.get("AuthorizerType") for a in authorizers]

        tags = api.get("Tags", {}) or {}

        properties = {
            "api_id": api_id,
            "name": api.get("Name"),
            "protocol_type": api.get("ProtocolType"),
            "endpoint": api.get("ApiEndpoint"),
            "is_websocket": api.get("ProtocolType") == "WEBSOCKET",
            "disable_execute_api_endpoint": api.get("DisableExecuteApiEndpoint", False),
            "has_authorizer": bool(authorizers),
            "authorizer_types": authorizer_types,
            "cors_allow_origins": cors_allow_origins,
            "cors_allows_all_origins": "*" in cors_allow_origins,
            "route_selection_expression": api.get("RouteSelectionExpression"),
        }

        return Resource(
            arn=arn,
            resource_type=ResourceType.API_GATEWAY_HTTP_API,
            name=api.get("Name", api_id),
            region=region,
            account_id=self.session.account_id,
            tags=tags,
            properties=properties,
        )
