import uuid
from sentence_transformers import SentenceTransformer
from src.modules.embeddings.qdrant_client import client, COLLECTION_NAME

model = SentenceTransformer('all-MiniLM-L6-v2')

def chunk_text(text: str, chunk_size: int = 500, overlap: int = 50) -> list[str]:
    chunks = []
    start = 0
    while start < len(text):
        end = start + chunk_size
        chunks.append(text[start:end])
        start += chunk_size - overlap #move forward, but overlap a bit with the previous chunk
    return chunks

def embed_and_store(text: str, user_id: str, record_id: str) -> list[dict]:
    """
    Embeds the given text using the SentenceTransformer model and returns a list of dictionaries
    containing the chunk ID, chunk text, and embedding vector.

    Args:
        text (str): The text to be embedded.
        user_id (str): The ID of the user who owns the text.
        record_id (str): The ID of the record to which the text belongs.

    Returns:
        list[dict]: A list of dictionaries containing the chunk ID, chunk text, and embedding vector.
    """
    chunks = chunk_text(text)
    for chunk in chunks:
        if not chunk.strip():  # Skip empty chunks
            continue
        
        vector = model.encode(chunk).tolist()
        # Store the vector in Qdrant
        client.upsert(
            collection_name=COLLECTION_NAME,
            points=[
                {
                    "id": str(uuid.uuid4()),  # Generate a unique ID for each chunk
                    "vector": vector,
                    "payload": {
                        "user_id": user_id,
                        "record_id": record_id,
                        "text": chunk
                    },
                }
            ],
        )
