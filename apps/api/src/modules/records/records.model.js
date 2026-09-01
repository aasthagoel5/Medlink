const mongoose = require ('mongoose');

const recordSchema = new mongoose.Schema({
  owner: {type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true},
  type: {
    type: String,
    enum: ['prescription', 'lab_report', 'scan', 'caccination', 'other'],
    required: true
  },
  fileUrl: {type: String, required: true},
  doctorName: {type: String},
  notes: {type: String },
  recordDate: {type: Date},
}, {timestamps: true});

module.exports = mongoose.model('Record', recordSchema);