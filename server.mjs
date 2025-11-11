import express from 'express';
import bodyParser from 'body-parser';
import nodemailer from 'nodemailer';
import { open } from 'sqlite'; 
import sqlite3 from 'sqlite3';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import 'dotenv/config'; // Loads environment variables from .env
import fs from 'fs';
import multer from 'multer';
import path from 'path';

// --- Configuration Constants ---
const JWT_SECRET = process.env.JWT_SECRET || 'FALLBACK_SECRET'; 
const PORT = process.env.PORT || 3000;
// Note: Changed FRONTEND_URL to '*' for maximum local CORS compatibility
const FRONTEND_URL = process.env.FRONTEND_URL || '*'; 
const saltRounds = 10;

// --- DATABASE: SQLite Configuration ---
const DB_FILE = './medlink.db';
let db; // This variable will hold our SQLite connection.

// --- OTP Storage: In-Memory Object (Wipes on server restart) ---
const otpStore = {}; 

const app = express();


// ====================================================================
// Utilities & Middleware
// ====================================================================

// --- Nodemailer Configuration (Uses .env) ---
const transporter = nodemailer.createTransport({
    service: 'Gmail',
    auth: { 
        user: process.env.EMAIL_USER, 
        pass: process.env.EMAIL_PASS
    }
});

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
        console.log(`OTP email sent successfully to ${to}`);
    } catch (error) {
        // Log the error but DO NOT crash the server, so the client receives the userId.
        console.error(`ERROR: Failed to send OTP email to ${to}:`, error.message);
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

// --- Multer Configuration ---
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
app.use(express.static(path.join(process.cwd(), '')));
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
// DATABASE INITIALIZATION
// ====================================================================

async function initDatabase() {
    try {
        // Open the SQLite database file (it will create it if it doesn't exist)
        db = await open({
            filename: DB_FILE,
            driver: sqlite3.Database
        });

        // Create all necessary tables
        await db.exec(`
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT DEFAULT (datetime('now', 'localtime')),
                is_verified INTEGER DEFAULT 0
            );
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


// server.mjs

// ... (after initDatabase function) ...

async function clearAllUsers() {
    try {
        console.log("--- STARTING DATABASE CLEANUP ---");
        
        // 1. Delete all records from tables dependent on users (Vitals and Files)
        await db.run("DELETE FROM vitals");
        await db.run("DELETE FROM medical_files");
        console.log("Cleaned dependent tables: vitals and medical_files.");

        // 2. Delete ALL records from the users table
        const result = await db.run("DELETE FROM users");
        console.log(`SUCCESS: Deleted ${result.changes} user record(s) from 'users' table.`);
        
        // 3. Reset the AUTOINCREMENT counter (SQLite specific command)
        await db.run("DELETE FROM sqlite_sequence WHERE name='users'");
        console.log("SUCCESS: Reset user ID counter.");

        console.log("--- DATABASE CLEANUP COMPLETE ---");
    } catch (error) {
        console.error("ERROR during database cleanup:", error);
    }
}

// ====================================================================
// API Endpoints
// ====================================================================

// POST /api/register - User Registration
app.post('/api/register', async (req, res) => {
    const { username, email, password } = req.body;
    
    if (!username || !email || !password) {
        return res.status(400).json({ success: false, message: 'All fields are required' });
    }
    
    try {
        // Check for existing user first (SQLite specific check)
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
        
        const userId = result.lastID;
        
        if (!userId) {
            throw new Error("Database insert failed: No user ID returned.");
        }

        // OTP Generation and In-Memory Storage
        const otp = generateOTP(); 
        const otp_expire = Date.now() + (5 * 60 * 1000); 
        otpStore[userId] = { otp, expires: otp_expire };
        
        console.log(`*** NEW USER OTP IS: ${otp} for User ID: ${userId} ***`); 

        // Send Email (Error will be logged but won't crash the server)
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
        const user = await db.get('SELECT * FROM users WHERE email = ?', [email]);
        
        if (!user) {
            return res.status(400).json({ success: false, message: 'Invalid email or password' });
        }
        
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
        
        // In-Memory OTP Storage
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
        
        // Check for missing OTP or expiration
        if (!storedOtpData || storedOtpData.expires < Date.now()) {
            return res.status(404).json({ success: false, message: 'OTP not found or expired' });
        }
        
        // Check for invalid code
        if (otp !== storedOtpData.otp) {
            return res.status(400).json({ success: false, message: 'Invalid OTP' });
        }
        
        delete otpStore[userId]; // Delete OTP after successful verification
        
        // 1. Update User Verification Status
        const updateResult = await db.run(
            'UPDATE users SET is_verified = 1 WHERE id = ?', 
            [userId]
        );
        
        if (updateResult.changes === 0) {
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

// --- Other Endpoints (Truncated for brevity, but exist in full code) ---
// app.post('/api/upload', authenticateToken, ...
// app.get('/api/reports/list/:category', authenticateToken, ...
// app.get('/api/download/:fileId', authenticateToken, ...
// app.post('/api/record/vital', authenticateToken, ...
// app.get('/api/vitals/hitory', authenticateToken, ...
// app.get('/api/user/profile', authenticateToken, ...
// app.put('/api/user/profile', authenticateToken, ...


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