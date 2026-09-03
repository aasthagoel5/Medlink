import os
import pytesseract
from PIL import Image
import io

pytesseract.pytesseract.tesseract_cmd = os.getenv("TESSERACT_PATH", r"C:\Program Files\Tesseract-OCR\tesseract.exe")

def extract_text_from_image(image_bytes: bytes) -> dict:
    """
    Extracts text from an image using Tesseract OCR.

    Args:
        image_bytes (bytes): The image data in bytes.

    Returns:
        str: The extracted text from the image.
    """
    image = Image.open(io.BytesIO(image_bytes))

    #get both text and confidence data from the image
    text = pytesseract.image_to_string(image)
    data = pytesseract.image_to_data(image, output_type=pytesseract.Output.DICT)

    #get the average confidence of the text
    confidences = [int(c) for c in data['conf'] if int(c) > 0]
    avg_confidence = sum(confidences) / len(confidences) if confidences else 0

    return {
        "text": text.strip(),
        "confidence": round(avg_confidence, 1),
    }
