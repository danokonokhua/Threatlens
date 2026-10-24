from elasticsearch import AsyncElasticsearch
from ..config import settings

es_client = AsyncElasticsearch(hosts=[settings.ELASTICSEARCH_URL])

INDEX_NAME = "threatlens_indicators"

async def create_index_if_not_exists():
    """Creates the Elasticsearch index with optimized mappings for threat hunting."""
    index_mapping = {
        "mappings": {
            "properties": {
                "id": {"type": "keyword"},
                "value": {
                    "type": "text",
                    "fields": {
                        "keyword": {"type": "keyword", "ignore_above": 256}
                    }
                },
                "type": {"type": "keyword"},
                "severity_score": {"type": "integer"},
                "confidence": {"type": "integer"},
                "status": {"type": "keyword"},
                "first_seen": {"type": "date"},
                "last_seen": {"type": "date"},
                "sources": {"type": "keyword"}
            }
        },
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0
        }
    }
    
    try:
        # In elasticsearch-py v8, exists() returns a boolean directly
        exists = await es_client.indices.exists(index=INDEX_NAME)
        if not exists:
            await es_client.indices.create(index=INDEX_NAME, body=index_mapping)
            print(f"✅ Created Elasticsearch index: {INDEX_NAME}")
        else:
            print(f"ℹ️ Elasticsearch index {INDEX_NAME} already exists.")
    except Exception as e:
        print(f"⚠️ Error checking/creating ES index: {e}")

async def sync_indicator_to_es(indicator_dict: dict):
    """Upserts a single indicator into Elasticsearch."""
    try:
        await es_client.index(
            index=INDEX_NAME,
            id=str(indicator_dict["id"]),
            document=indicator_dict,
            refresh="true" # Force immediate refresh for sub-second searchability
        )
    except Exception as e:
        print(f"❌ Failed to sync indicator {indicator_dict.get('id')} to ES: {e}")

async def search_indicators(
    query: str = "",
    type_filter: str = "",
    min_score: int = 0,
    status_filter: str = "active",
    size: int = 50
):
    """Performs a faceted, full-text search in Elasticsearch."""
    es_query = {
        "bool": {
            "filter": []
        }
    }

    # 1. Full-text search on 'value' (if query provided)
    if query:
        es_query["bool"]["must"] = {
            "multi_match": {
                "query": query,
                "fields": ["value", "value.keyword"],
                "fuzziness": "AUTO"
            }
        }

    # 2. Faceted Filters
    if type_filter:
        es_query["bool"]["filter"].append({"term": {"type": type_filter}})
    
    if status_filter:
        es_query["bool"]["filter"].append({"term": {"status": status_filter}})
        
    if min_score > 0:
        es_query["bool"]["filter"].append({"range": {"severity_score": {"gte": min_score}}})

    # If no 'must' clause, use match_all to satisfy ES syntax
    if "must" not in es_query["bool"]:
        es_query["bool"]["must"] = {"match_all": {}}

    response = await es_client.search(
        index=INDEX_NAME,
        body={
            "query": es_query,
            "size": size,
            "sort": [{"severity_score": {"order": "desc"}}, {"last_seen": {"order": "desc"}}]
        }
    )
    
    # Format response
    hits = response["hits"]["hits"]
    return [
        {
            "id": hit["_id"],
            **hit["_source"]
        } for hit in hits
    ]