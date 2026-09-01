const express = require('express');
const router = express.Router();
const authGuard = require('../../middleware/authGuard');
const upload = require('./records.upload');
const { createRecord, getRecord, getRecordById, deleteRecord } = require('./records.controller');

router.post('/', authGuard, upload.single('file'), createRecord);
router.get('/', authGuard, getRecord);
router.get('/:id', authGuard, getRecordById);
router.delete('/:id', authGuard, deleteRecord);

module.exports = router;
