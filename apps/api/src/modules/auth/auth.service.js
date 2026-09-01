const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('./auth.model');

const hashPassword = async (plainPassword) => {
  const salt = await bcrypt.genSalt(10); // "10 rounds" — a standard cost factor
  return bcrypt.hash(plainPassword, salt);
};

const comparePassword = async (plainPassword, hashedPassword) => {
  return bcrypt.compare(plainPassword, hashedPassword);
};

const generateToken = (userId) => {
  return jwt.sign({ id: userId }, process.env.JWT_SECRET, { expiresIn: '7d' });
};

module.exports = { hashPassword, comparePassword, generateToken };

