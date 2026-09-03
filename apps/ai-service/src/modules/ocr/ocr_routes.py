from fastapi import APIRouter, UploadFile, File, HTTPException
from fastapi.responses import JSONResponse
from src.modules.ocr.ocr_service import extract_text_from_image

router = APIRouter(prefix="/ocr", tags=["OCR"])

@router.post("/extract")
async def run_ocr(file: UploadFile = File(...)):
    print("Received content_type:", file.content_type)
    if file.content_type not in ["image/jpeg", "image/png", "image/jpg", "application/octet-stream"]:
        raise HTTPException(status_code=400, detail="Only JPEG/PNG images are supported for OCR right now")

    image_bytes = await file.read()
    try:
        result = extract_text_from_image(image_bytes)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"OCR failed: {str(e)}")

    

