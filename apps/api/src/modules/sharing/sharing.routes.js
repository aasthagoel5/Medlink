const express = require('express');
const router = express.Router();
const authGuard = require('../../middleware/authGuard');
const { createShareLink, getActiveLink, revokeLink, resolveSharedRecord } = require('./sharing.controller');

router.post('/', authGuard, createShareLink);       // owner creates a link — needs login
router.get('/active', authGuard, getActiveLink);   // owner views their active links
router.delete('/:id', authGuard, revokeLink);       // owner revokes a link
router.get('/:token', resolveSharedRecord);         // PUBLIC — no authGuard, this is what the doctor opens

module.exports = router;
