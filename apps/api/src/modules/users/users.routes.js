const express = require('express');
const router = express.Router();
const authGuard = require('../../middleware/authGuard');
const { getMe, updateMe } = require('./users.controller');

router.get('/me', authGuard, getMe);
router.put('/me', authGuard, updateMe);

module.exports = router;