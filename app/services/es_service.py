from __future__ import annotations

from datetime import datetime
from typing import Any

from elasticsearch import AsyncElasticsearch

from app.core.config import settings


def _build_client() -> AsyncElasticsearch:
    verify = settings.WORM_VERIFY_SSL
    ca_certs = settings.ES_CA_CERT_PATH if verify else None
    return AsyncElasticsearch(
        hosts=[settings.ES_URL],
        basic_auth=(settings.ES_USER, settings.ES_PASSWORD),
        verify_certs=verify,
        ca_certs=ca_certs,
    )


async def fetch_ocsf_events(start: datetime, end: datetime, query_text: str | None = None) -> list[dict[str, Any]]:
    body: dict[str, Any] = {
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": start.isoformat(), "lte": end.isoformat()}}}
                ]
            }
        },
        "sort": [{"@timestamp": {"order": "desc"}}],
        "size": 1000,
    }
    if query_text:
        body["query"]["bool"]["must"] = [{"query_string": {"query": query_text}}]

    client = _build_client()
    try:
        resp = await client.search(index=settings.OCSF_INDEX_PATTERN, body=body)
        return [hit["_source"] for hit in resp["hits"]["hits"]]
    finally:
        await client.close()
