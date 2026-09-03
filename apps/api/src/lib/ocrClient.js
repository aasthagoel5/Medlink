const axios = require('axios');
const FormData = require('form-data');

const extractTextFromImage = async (imageUrl, userId, recordId) => {
  // step 1: download the image bytes from Cloudinary's URL
  const imageResponse = await axios.get(imageUrl, { responseType: 'arraybuffer' });
  const imageBuffer = Buffer.from(imageResponse.data, 'binary');

  // step 2: ebuild it as a multipart form, same shape the FastAPI endpoint expects
  const formData = new FormData();
  formData.append('file', imageBuffer, { filename: 'record.jpg', contentType: 'image/jpeg' });
  formData.append('user_id', userId);
  formData.append('record_id', recordId);

  // step 3: send it to our Python service
  const ocrResponse = await axios.post(`${process.env.AI_SERVICE_URL}/ocr/extract`, formData, {
    headers: formData.getHeaders(),
  });

  return ocrResponse.data; // { text, confidence }
};

module.exports = { extractTextFromImage };
