const Record = require('./records.model');
const { extractTextFromImage } = require('../../lib/ocrClient');

const createRecord = async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: 'No file uploaded' });
    }

    const { type, doctorName, notes, recordDate } = req.body;

    // create the record first, so we have a real recordId to tag the embeddings with
    const record = await Record.create({
      owner: req.userId,
      type,
      fileUrl: req.file.path,
      doctorName,
      notes,
      recordDate,
    });

    // now run OCR + embedding, and update the record with the results
    try {
      const ocrResult = await extractTextFromImage(req.file.path, req.userId.toString(), record._id.toString());
      record.extractedText = ocrResult.text;
      record.ocrConfidence = ocrResult.confidence;
      await record.save();
    } catch (ocrErr) {
      console.error('OCR failed, record saved without extracted text:', ocrErr.message);
    }

    res.status(201).json(record);
  } catch (err) {
    res.status(500).json({ message: 'Upload failed', error: err.message });
  }
};

const getRecord = async (req,res) => {
  try{
    const records = await Record.find({owner : req.userId}).sort({ createdAt: -1});
    res.status(200).json(records);
  }catch(err){
    res.status(500).json({message: 'Failed to fetch records', erroe: err.message});
  }
};

const getRecordById = async (req, res) => {
  try{
    const record = await Record.findOne({ _id: req.params.id, owner: req.userId });
    if (!record) {
      return res.status(404).json({ message: 'Record not found' });
    }
    res.status(200).json(record);
  }catch(err){
    res.status(500).json({message: 'Failed to fetch record', error: err.message});
  }
};

const deleteRecord = async (req, res) => {
  try{
    const record = await Record.findOneAndDelete({ _id: req.params.id, owner: req.userId });
    if (!record) {
      return res.status(404).json({ message: 'Record not found' });
    }
    res.status(200).json({message: 'Record deleted'});
  }  catch(err){
    res.status(500).json({message:'Delete failed', error: err.message });
  }
};

module.exports = {createRecord, getRecord, getRecordById, deleteRecord};


