import express from 'express';
import bodyParser from 'body-parser';
import nodemailer from 'nodemailer';
import {open} from 'sqlite';
import sqlite3 from 'sqlite3';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import 'process/config'; // Loads environment variables from .env
console.log("--- DEBUG: EMAIL USER ---", process.env.EMAIL_USER); // <--- ADD THIS
console.log("--- DEBUG: EMAIL PASS ---", process.env.EMAIL_PASS); // <--- ADD THIS
import fs from 'fs';
import multer from 'multer';
import path from 'path';

// --- Configuration Constants ---
const JWT_SECRET = process.env.JWT_SECRET || 'FALLBACK_SECRET'; 
const PORT = process.env.PORT || 3000;
const FRONTEND_URL = process.env.FRONTEND_URL || '*';
const saltRounds = 10;

// --- DATABASE: SQLite Configuration ---
// The entire database will be stored in this file.
const DB_FILE = './medlink.db';
let db; // This variable will hold our SQLite connection.

// --- OTP Storage: In-Memory Object (Simple Replacement for Redis) ---
// Keys: userId, Values: { otp: '1234', expires: 1678888888 }
const otpStore = {}; 

const app = express();


// ====================================================================
// YOU SHOULD NOT REMOVE THESE PARTS: Utilities & Middleware
// ====================================================================

// --- Utility Functions ---

function generateOTP() {
    return Math.floor(1000 + Math.random() * 9000).toString();
}

async function sendOTPEmail(to, otp) {
    // ... (Your Nodemailer setup remains the same)
    // NOTE: For this to work, EMAIL_USER and EMAIL_PASS must be in .env
    const transporter = nodemailer.createTransport({
        service: 'Gmail',
        auth: { 
            user: process.env.EMAIL_USER, 
            pass: process.env.EMAIL_PASS
        }
    });

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
        // We need to catch this but let the registration proceed to OTP screen
        console.error(`Error sending OTP email to ${to}:`, error.message);
    }
}

function authenticateToken(req, res, next) {
    // ... (Your JWT token verification remains the same)
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.status(401).json({ success: false, message: 'No token provided' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ success: false, message: 'Invalid token' });
        req.user = user;
        next();
    });
}

// --- Multer Configuration ---
// ... (Your Multer setup remains the same)
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
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
    limits: { fileSize: 10 * 1024 * 1024 } 
}).single('medicalFile');


// --- Express Middleware ---
app.use(bodyParser.json());
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', FRONTEND_URL); 
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
    
    if ('OPTIONS' === req.method) {
        return res.sendStatus(200); 
    }
    next();
});

// ====================================================================
// DATABASE INITIALIZATION (NEW/CHANGED PART)
// ====================================================================

async function initDatabase() {
    try {
        // Open the SQLite database file (it will create it if it doesn't exist)
        db = await open({
            filename: DB_FILE,
            driver: sqlite3.Database
        });

        // 1. Create the users table
        await db.exec(`
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT DEFAULT (datetime('now', 'localtime')),
                is_verified INTEGER DEFAULT 0
            );
        `);
        // 2. Create the vitals table
        await db.exec(`
            CREATE TABLE IF NOT EXISTS vitals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                systolic_bp INTEGER NOT NULL,
                diastolic_bp INTEGER NOT NULL,
                heart_rate INTEGER NOT NULL,
                temperature REAL NOT NULL,
                weight REAL NOT NULL,
                notes TEXT,
                recorded_at TEXT DEFAULT (datetime('now', 'localtime')),
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
        `);
        // 3. Create the medical_files table
        await db.exec(`
            CREATE TABLE IF NOT EXISTS medical_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                filename TEXT NOT NULL,
                filepath TEXT NOT NULL,
                mimetype TEXT,
                size INTEGER,
                category TEXT,
                upload_date TEXT DEFAULT (datetime('now', 'localtime')),
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
        `);

        console.log('Database Check: Success! SQLite tables created/verified.');
    } catch (error) {
        console.error("CRITICAL: Failed to initialize SQLite database:", error.message);
        process.exit(1);
    }
}


// ====================================================================
// API Endpoints (MODIFIED FOR SQLITE SYNTAX)
// ====================================================================

// POST /api/register - User Registration
app.post('/api/register', async (req, res) => {
    const { username, email, password } = req.body;
    
    if (!username || !email || !password) {
        return res.status(400).json({ success: false, message: 'All fields are required' });
    }
    
    try {
        // Check for existing user first (due to UNIQUE constraint handling differences)
        const existingUser = await db.get('SELECT id FROM users WHERE email = ? OR username = ?', [email, username]);
        if (existingUser) {
            return res.status(409).json({ success: false, message: 'Username or email already exists.' });
        }

        const hashedPassword = await bcrypt.hash(password, saltRounds); 
        
        // SQLite Insert
        const result = await db.run(
            'INSERT INTO users (username, email, password_hash, is_verified) VALUES (?, ?, ?, 0)', 
            [username, email, hashedPassword]
        );
        
        const userId = result.lastID; // SQLite uses lastID instead of insertId
        
        if (!userId) {
            throw new Error("Database insert failed: No user ID returned.");
        }

        // server.mjs - inside app.post('/api/register', ...)
// ...
// OTP Generation and In-Memory Storage
        const otp = generateOTP(); 
        console.log(`NEW USER OTP IS: ${otp}`); // <--- ADD THIS LINE
        const otp_expire = Date.now() + (5 * 60 * 1000); 
        otpStore[userId] = { otp, expires: otp_expire };
        // ...
        // Send Email
        await sendOTPEmail(email, otp);
        
        // Final Success Response
        return res.json({ success: true, message: 'User registered successfully. OTP sent to email.', userId });
        
    } catch (error) {
        console.error('SERVER CRITICAL RUNTIME FAILURE:', error);
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
        // SQLite: use db.get() for a single row
        const user = await db.get('SELECT * FROM users WHERE email = ?', [email]);
        
        if (!user) {
            return res.status(400).json({ success: false, message: 'Invalid email or password' });
        }
        
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
    
    try{
        const user = await db.get('SELECT email FROM users WHERE id = ?', [userId]);
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }
        const userEmail = user.email;
        
        // In-Memory OTP Storage (Replaces Redis logic)
        const newotp = generateOTP();
        const otp_expire = Date.now() + (5 * 60 * 1000); 
        otpStore[userId] = { otp: newotp, expires: otp_expire };

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
        const storedOtpData = otpStore[userId];
        
        if (!storedOtpData || storedOtpData.expires < Date.now()) {
            return res.status(404).json({ success: false, message: 'OTP not found or expired' });
        }
        
        if (otp !== storedOtpData.otp) {
            return res.status(400).json({ success: false, message: 'Invalid OTP' });
        }
        
        delete otpStore[userId]; // Delete OTP after successful verification
        
        // 1. Update User Verification Status
        const updateResult = await db.run(
            'UPDATE users SET is_verified = 1 WHERE id = ?', 
            [userId]
        );
        
        if (updateResult.changes === 0) { // SQLite uses .changes instead of affectedRows
            return res.status(404).json({ success: false, message: 'Verification failed: User not found.' });
        }
        
        // 2. Fetch the user record for token generation
        const user = await db.get(
            'SELECT id, username FROM users WHERE id = ?', 
            [userId]
        );

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


// ... (Other endpoints like /api/upload, /api/reports/list, /api/download, /api/record/vital, /api/vitals/hitory, /api/user/profile remain the same with slight SQLITE query adjustments: db.get(), db.all(), db.run()) ...

// --- Server Startup ---
async function startServer() {
    console.log('----------------------------------------------------');
    
    // CRITICAL: Initialize SQLite database before starting server
    await initDatabase(); 
    
    app.listen(PORT, () => { 
        console.log(`Server is running on http://localhost:${PORT}`);
        console.log(`Frontend CORS set to: ${FRONTEND_URL}`);
        console.log('----------------------------------------------------');
    });
}

startServer();