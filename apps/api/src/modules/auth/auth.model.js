const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true, lowercase: true },
  password: { type: String, required: true }, // stores the HASHED password, never plain text
  bloodGroup: { type: String },
  allergies: [{ type: String }],
  chronicConditions: [{ type: String }],
  dateOfBirth: { type: Date },
  emergencyContact: [{
    name: { type: String },
    phone: { type: String },
    relation: { type: String }
  }],
  tier: { type: String, enum: ['web2', 'web3'], default: 'web2' },
}, { timestamps: true});  // adds createdAt/updatedAt automatically

module.exports = mongoose.model('User', userSchema);
