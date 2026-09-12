from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from src.modules.ocr.ocr_routes import router as ocr_router
from src.modules.embeddings.qdrant_client import ensure_collection_exists, ensure_userid_index_exists
from src.modules.chat.chat_routes import router as chat_router 



app = FastAPI()
app.include_router(chat_router)
ensure_collection_exists()
ensure_userid_index_exists()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5000"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(ocr_router)
app.include_router(chat_router)

@app.get("/health")
def health_check():
  return {"status": "ok", "message": "Medlink ai Service is running"}
