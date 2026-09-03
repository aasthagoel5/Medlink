from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from src.modules.ocr.ocr_routes import router as ocr_router

load_dotenv()

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5000"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(ocr_router)

@app.get("/health")
def health_check():
  return {"status": "ok", "message": "Medlink ai Service is running"}