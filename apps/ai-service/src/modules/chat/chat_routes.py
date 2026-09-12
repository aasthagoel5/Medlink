from fastapi import APIRouter , HTTPException
from pydantic import BaseModel
from src.modules.chat.chat_service import ask_question

router = APIRouter(prefix="/chat", tags=["chat"])

class ChatRequest(BaseModel):
  question : str
  user_id:str
@router.post("/ask")
async def chat(request: ChatRequest):
  try:
    result = ask_question(request.question, request.user_id)
    return result
  except Exception as e:
    raise HTTPException(status_code=500, detail=f"Chat service failed: {str(e)}")

























































