const express = require('express');
const cors = require('cors');
require('dotenv').config();
const connectDB = require('./config/db');  
const authRoutes = require('./modules/auth/auth.routes');
const recordsRoutes = require('./modules/records/records.routes'); 
const sharingRoutes = require('./modules/sharing/sharing.routes');

connectDB();   

const app = express();

app.use(cors());
app.use(express.json());
app.use('/auth', authRoutes);
app.use('/records', recordsRoutes);
app.use('/sharing', sharingRoutes);

// global error handler — must be defined AFTER all routes
app.use((err, req, res, next) => {
  console.error('FULL ERROR OBJECT:', err);
  res.status(500).json({
    message: err.message || 'Something went wrong',
    name: err.name,
  });
});

// quick health check route
app.get('/health', (req, res) => {
  res.json({ status: 'ok', message: 'MEDLINK API is running' });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});