import os
from qdrant_client import QdrantClient
from qdrant_client.models import  VectorParams, Distance

client = QdrantClient(
    url=os.getenv("QDRANT_URL"),
    api_key=os.getenv("QDRANT_API_KEY"),
)

COLLECTION_NAME = "medical_records"
VECTOR_SIZE = 384 #matches all-MiniLM-L6-v2's output size

def ensure_collection_exists():
    """
    Ensures that the Qdrant collection exists. If it doesn't, create it.
    """
    collections = client.get_collections().collections
    exists = any(c.name == COLLECTION_NAME for c in collections)

    if not exists:
        client.recreate_collection(
            collection_name=COLLECTION_NAME,
            vectors_config=VectorParams(size=VECTOR_SIZE, distance=Distance.COSINE)
        )
