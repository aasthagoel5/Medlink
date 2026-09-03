from fastapi import APIRouter, Form, UploadFile, File, HTTPException
from fastapi.responses import JSONResponse
from src.modules.ocr.ocr_service import extract_text_from_image
from src.modules.embeddings.embed_service import embed_and_store

router = APIRouter(prefix="/ocr", tags=["OCR"])

@router.post("/extract")
async def run_ocr(file: UploadFile = File(...), user_id: str = Form(...), record_id: str = Form(...)):
    print("Received content_type:", file.content_type)
    if file.content_type not in ["image/jpeg", "image/png", "image/jpg", "application/octet-stream"]:
        raise HTTPException(status_code=400, detail="Only JPEG/PNG images are supported for OCR right now")

    image_bytes = await file.read()
    try:
        result = extract_text_from_image(image_bytes)

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"OCR failed: {str(e)}")

    # embed and store — but don't let a failure here break the OCR response
    if result["text"]:
        try:
            embed_and_store(result["text"], user_id, record_id)
        except Exception as e:
            print(f"Embedding failed (non-fatal): {e}")

    return result

    

