import express from 'express';
import bodyParser from 'body-parser';
import nodemailer from 'nodemailer';
import Redis from 'ioredis';
import mysql from 'mysql2/promise';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import 'dotenv/config'; // Loads environment variables from .env
import fs from 'fs';
import multer from 'multer';
import path from 'path';

// --- Configuration Constants ---
// CRITICAL: Uses environment variables for deployment
const JWT_SECRET = process.env.JWT_SECRET || 'FALLBACK_SECRET'; 
const PORT = process.env.PORT || 3000;
const FRONTEND_URL = process.env.FRONTEND_URL || '*';
const saltRounds = 10;
const otpStore = {}; 

const app = express();
const redis = new Redis();

// --- Multer Configuration ---
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        // Ensure the 'uploads/' directory exists
        const uploadDir = 'uploads/';
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir);
        }
        cb(null, uploadDir);
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});
const upload = multer({ 
    storage: storage,
    limits: { fileSize: 10 * 1024 * 1024 } // 10 MB limit
}).single('medicalFile');

// --- Nodemailer Configuration (Uses .env) ---
const transporter = nodemailer.createTransport({
    service: 'Gmail',
    auth: { 
        user: process.env.EMAIL_USER, 
        pass: process.env.EMAIL_PASS
    }
});

// --- MySQL Database Pool Setup (Uses .env) ---
const db = mysql.createPool({ 
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// --- Utility Functions ---

function generateOTP() {
    return Math.floor(1000 + Math.random() * 9000).toString();
}

async function sendOTPEmail(to, otp) {
    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: to,
        subject: 'Your OTP Code',
        text: `Your OTP code is ${otp}`
    };
    try {
        await transporter.sendMail(mailOptions);
        console.log(`OTP email sent to ${to}`);
    } catch (error) {
        console.error(`Error sending OTP email to ${to}:`, error.message);
    }
}

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.status(401).json({ success: false, message: 'No token provided' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ success: false, message: 'Invalid token' });
        req.user = user;
        next();
    });
}

// --- Database Schema Check (Run on startup) ---
async function checkDatabaseSchema() {
    try {
        const [columns] = await db.execute("DESCRIBE users");
        const columnNames = columns.map(col => col.Field);
        
        if (!columnNames.includes('username') || !columnNames.includes('is_verified')) {
             console.error("\n*** CRITICAL SCHEMA MISMATCH DETECTED ***");
             console.error("The 'users' table is MISSING 'username' or 'is_verified' columns.");
             process.exit(1);
        }
    } catch (error) {
        console.error("\n*** CRITICAL: Failed to connect or find 'users' table! ***");
        console.error("Is your MySQL server running? Error:", error.message);
        // Do not exit in production, but alert. For development, we exit.
        if (process.env.NODE_ENV !== 'production') process.exit(1); 
    }
}
// ----------------------------------------------------------------------


// --- Express Middleware ---
app.use(bodyParser.json());

// CORS Configuration (Updated for deployment security)
app.use((req, res, next) => {
    // For production, replace '*' with your actual domain using FRONTEND_URL
    res.header('Access-Control-Allow-Origin', FRONTEND_URL); 
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
    
    // Handle preflight requests
    if ('OPTIONS' === req.method) {
        return res.sendStatus(200); 
    }
    next();
});

// --- API Endpoints ---

// POST /api/register - User Registration
app.post('/api/register', async (req, res) => {
    const { username, email, password } = req.body;
    
    if (!username || !email || !password) {
        return res.status(400).json({ success: false, message: 'All fields are required' });
    }
    
    try {
        // 1. CRITICAL FIX: Password Hashing
        const hashedPassword = await bcrypt.hash(password, saltRounds); 
        
        // 2. Database Insert
        const [rows] = await db.execute(
            'INSERT INTO users (username, email, password_hash, created_at, is_verified) VALUES (?, ?, ?, NOW(), 0)', 
            [username, email, hashedPassword]
        );
        
        const userId = rows.insertId; 
        
        if (!userId) {
            throw new Error("Database insert failed: No user ID returned.");
        }

        // 3. OTP Generation and Redis Storage
        const otp = generateOTP();
        const otp_expire = 300; // 5 minutes
        await redis.set(`otp:${userId}`, otp, 'EX', otp_expire);
        
        // 4. Send Email (Must use App Password for production)
        await sendOTPEmail(email, otp);
        
        // 5. Final Success Response
        return res.json({ success: true, message: 'User registered successfully. OTP sent to email.', userId });
        
    } catch (error) {
        console.error('SERVER CRITICAL RUNTIME FAILURE:', error);
        
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ success: false, message: 'Username or email already exists' });
        }
        
        return res.status(500).json({ success: false, message: 'Internal server error: Check server logs for details.' });
    }
});

// POST /api/login - User Login
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ success: false, message: 'Email and password are required' });
    }

    try {
        const [rows] = await db.execute('SELECT * FROM users WHERE email = ?', [email]);
        if (rows.length === 0) {
            return res.status(400).json({ success: false, message: 'Invalid email or password' });
        }
        const user = rows[0];
        
        // Compare hashed password
        const passwordMatch = await bcrypt.compare(password, user.password_hash);
        if (!passwordMatch) {
            return res.status(401).json({ success: false, message: 'Invalid email or password' });
        }
        
        if(!user.is_verified){
            return res.status(403).json({ success: false, message: 'Email not verified. Please verify your account.' });
        }
        
        const token = jwt.sign({ userId: user.id, username: user.username }, JWT_SECRET, { expiresIn: '1h' });
        return res.json({ success: true, message: 'Login successful', token });
    } catch (error) {
        console.error('Error during login:', error);
        return res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

// POST /api/resend-otp
app.post('/api/resend-otp', async (req, res) => {
    const { userId } = req.body;
    const otp_expire = 300; 

    try{
        const [userRows] = await db.execute('SELECT email FROM users WHERE id = ?', [userId]);
        if (userRows.length === 0) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }
        const userEmail = userRows[0].email;
        
        const newotp = generateOTP();
        await redis.set(`otp:${userId}`, newotp, 'EX', otp_expire);
        await sendOTPEmail(userEmail, newotp); 
        
        console.log(`Resent OTP for user ${userId}: ${newotp}`);
        return res.json({ success: true, message: 'OTP resent successfully!' });
    } catch (error) {
        console.error(`Error resending OTP for user ${userId}:`, error);
        return res.status(500).json({ success: false, message: 'Internal server error' }); 
    }
});

// POST /api/verify-otp
app.post('/api/verify-otp', async (req, res) => {
    const { userId, otp } = req.body;
    
    if (!userId || !otp) {
        return res.status(400).json({ success: false, message: 'User ID and OTP are required' });
    }

    try {
        const storedOtp = await redis.get(`otp:${userId}`);
        
        if (!storedOtp) {
            return res.status(404).json({ success: false, message: 'OTP not found or expired' });
        }
        
        if (otp !== storedOtp) {
            return res.status(400).json({ success: false, message: 'Invalid OTP' });
        }
        
        await redis.del(`otp:${userId}`); 
        
        // 1. Update User Verification Status
        const [updateResult] = await db.execute(
            'UPDATE users SET is_verified = 1 WHERE id = ?', 
            [userId]
        );
        
        if (updateResult.affectedRows === 0) {
            return res.status(404).json({ success: false, message: 'Verification failed: User not found.' });
        }
        
        // 2. Fetch the user record for token generation
        const [updatedUserRows] = await db.execute(
            'SELECT id, username FROM users WHERE id = ?', 
            [userId]
        );
        
        const user = updatedUserRows[0];

        // 3. Generate and Return JWT Token
        const token = jwt.sign({ userId: user.id, username: user.username }, JWT_SECRET, { expiresIn: '1h' });
        
        return res.json({ 
            success: true, 
            message: 'Email verified successfully. Login token provided.',
            token: token
        });
        
    } catch (error) {
        console.error('Error during OTP verification and login:', error);
        return res.status(500).json({ success: false, message: 'Internal server error' });
    }
});


app.post('/api/upload', authenticateToken, (req, res) => {
    upload(req, res, async function (err) {
        if (err instanceof multer.MulterError) {
            if (err.code === 'LIMIT_FILE_SIZE') {
                return res.status(400).json({ success: false, message: 'File too large (max 10MB)' });
            }
            return res.status(400).json({ success: false, message: err.message });
        } else if (err) {
            return res.status(500).json({ success: false, message: 'Unknown upload error' });
        }
        
        if (!req.file) {
            return res.status(400).json({ success: false, message: 'No file selected for upload.' });
        }

        const userId = req.user.userId;
        const { category } = req.body;
        const { filename, path: filePath, mimetype, size } = req.file;

        try{
            const [result] = await db.execute( 
                'INSERT INTO medical_files (user_id, filename, filepath, mimetype, size, category, upload_date) VALUES (?, ?, ?, ?, ?, ?, NOW())',
                [userId, filename, filePath, mimetype, size, category]
            );
            return res.status(201).json({ success: true, message: 'File uploaded successfully', fileId: result.insertId });
        } catch (error) {
            console.error('Error saving file information to database:', error);
            // Clean up file if database insert fails
            fs.unlink(filePath, () => {}); 
            return res.status(500).json({ success: false, message: 'Internal server error' });
        }
    });
});

app.get('/api/reports/list/:category', authenticateToken, async (req, res) => {
    const userId = req.user.userId;
    const categorySlug = req.params.category; // e.g., 'xray-files'

    if (!categorySlug) {
        return res.status(400).json({ success: false, message: 'Category is required' });
    }
    
    // Convert slug back to the database-friendly format: 'X-Ray Files' -> 'Xray Files'
    const dbCategory = categorySlug.split('-').map(word => word.charAt(0).toUpperCase() + word.slice(1)).join(' ');


    try {
        const [reports] = await db.execute(
            'SELECT id, filename, mimetype, size, upload_date FROM medical_files WHERE user_id = ? AND category = ? ORDER BY upload_date DESC',
            [userId, dbCategory]
        );
        
        if (reports.length === 0) {
            return res.status(404).json({ success: false, message: 'No reports found for this category', data: [] });
        }

        res.json({
            success: true,
            data: reports
        });
    } catch (error) {
        console.error('Error fetching reports:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

// GET /api/download/:fileId - File Download
app.get('/api/download/:fileId', authenticateToken, async (req, res) => {
    const userId = req.user.userId;
    const fileId = req.params.fileId;
    

    try{
        // Select file based on ID AND user_id for security
        const [rows] = await db.execute(
            'SELECT filename, filepath, mimetype FROM medical_files WHERE id = ? AND user_id = ?',
            [fileId, userId]
        );
        if (rows.length === 0) {
            return res.status(404).json({ success: false, message: 'File not found or access denied' });
        }
        
        const fileInfo = rows[0];
        
        if(!fs.existsSync(fileInfo.filepath)){
            return res.status(404).json({ success: false, message: 'File not found on server storage' });
        }
        
        // Download the file
        res.download(fileInfo.filepath, fileInfo.filename, (err) => {
            if (err) {
                console.error('Error downloading file:', err);
                if (!res.headersSent) {
                    res.status(500).json({ success: false, message: 'Internal server error during transfer' });
                }
            }
        });
    } catch (error) {
        console.error('Error fetching file for download:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

// ... (Other endpoints for vitals and profile remain unchanged) ...

app.post('/api/record/vital', authenticateToken, async (req, res) => {
    const user_id = req.user.userId; 
    const{
        systolic_bp,
        diastolic_bp,
        heart_rate,
        temperature,
        weight,
        notes
    }=req.body;

    if(!systolic_bp || !diastolic_bp || !heart_rate || !temperature || !weight){
        return res.status(400).json({ success: false, message: 'All vital fields are required' });

    }
    const sql=`INSERT INTO vitals
    (user_id, systolic_bp, diastolic_bp, heart_rate, temperature, weight, notes, recorded_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, NOW())`;
    const values=[
        user_id,
        systolic_bp,
        diastolic_bp,
        heart_rate,
        temperature,
        weight,
        notes || null
    ];
    try{
        const [result]=await db.execute(sql, values);
        console.log('Vital record inserted with ID:', result.insertId);
        res.status(201).json({ success: true, message: 'Vital record added successfully', vitalId: result.insertId });
    } catch (error) {
        console.error('Error inserting vital record:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

app.get('/api/vitals/hitory', authenticateToken, async (req, res) => { 
    const user_id = req.user.userId;
    const sql=`SELECT id, systolic_bp, diastolic_bp, heart_rate, temperature, weight, notes, recorded_at
    FROM vitals
    WHERE user_id = ?
    ORDER BY recorded_at DESC`;
    try{
        const [rows]=await db.execute(sql, [user_id]);
        if (rows.length === 0){
            return res.status(404).json({ success: false, message: 'No vitals history found', data:[]});
        }
        res.status(200).json({ success: true, data: rows });
    } catch (error) {
        console.error('Error fetching vitals history:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

app.get('/api/user/profile', authenticateToken, async (req, res) => { 
    const user_id = req.user.userId; 
    const sql = `SELECT id, username, email, created_at, is_verified
    FROM users
    WHERE id = ?`;
    try {
        const [result] = await db.execute(sql, [user_id]);
        if (result.length === 0) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }
        res.status(200).json({ success: true, data: result[0] });
    } catch (error) {
        console.error('Error fetching user profile:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

app.put('/api/user/profile', authenticateToken, async (req, res) => { 
    const user_id = req.user.userId;
    const { username, email } = req.body;
    if (!username && !email) {
        return res.status(400).json({ success: false, message: 'At least one field (username or email) is required' });
    }
    const sql = `UPDATE users SET
        username = COALESCE(?, username),
        email = COALESCE(?, email)
    WHERE id = ?`;
    const values = [username, email, user_id];
    try {
        const [result] = await db.execute(sql, values);
        if (result.affectedRows === 0) {
            return res.status(404).json({ success: false, message: 'User not found or no changes made' });
        }
        res.status(200).json({ success: true, message: 'User profile updated successfully' });
    } catch (error) {
        console.error('Error updating user profile:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});


// --- Server Startup ---
app.listen(PORT, async () => { 
    console.log('----------------------------------------------------');
    console.log(`Server is running on http://localhost:${PORT}`);
    console.log(`Frontend CORS set to: ${FRONTEND_URL}`);
    
    // Check database connection before fully starting
    await checkDatabaseSchema(); 
    console.log('Database Check: Success!');
    console.log('----------------------------------------------------');
});