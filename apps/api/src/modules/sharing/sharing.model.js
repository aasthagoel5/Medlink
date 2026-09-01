const mongoose = require('mongoose');
const crypto = require('crypto');

const shareLinkSchema = new mongoose.Schema({
  record: { type: mongoose.Schema.Types.ObjectId, ref: 'Record', required: true },
  owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  token: { type: String, required: true, unique: true, default: () => crypto.randomBytes(24).toString('hex') },
  expiresAt: { type: Date, required: true },
}, { timestamps: true });

module.exports = mongoose.model('ShareLink', shareLinkSchema);