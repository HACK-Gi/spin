// server.js
const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const dotenv = require('dotenv');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'spin-motion-secret-key-2024';

// Middleware
app.use(cors());
app.use(express.json());

// MySQL Connection
const db = mysql.createConnection({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'spin_motion_db'
});

db.connect((err) => {
    if (err) {
        console.error('Database connection failed:', err);
        return;
    }
    console.log('Connected to MySQL database');
});

// ==================== API Routes ====================

// Register
app.post('/api/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;

        // Validation
        if (!username || !email || !password) {
            return res.status(400).json({ 
                success: false, 
                message: 'សូមបំពេញព័ត៌មានទាំងអស់' 
            });
        }

        if (password.length < 6) {
            return res.status(400).json({ 
                success: false, 
                message: 'លេខសម្ងាត់ត្រូវតែយ៉ាងតិច 6 តួអក្សរ' 
            });
        }

        if (!email.includes('@') || !email.includes('.')) {
            return res.status(400).json({ 
                success: false, 
                message: 'សូមបញ្ចូលអ៊ីមែលឱ្យបានត្រឹមត្រូវ' 
            });
        }

        // Check if username or email exists
        const [existingUsers] = await db.promise().query(
            'SELECT id FROM users WHERE username = ? OR email = ?',
            [username, email]
        );

        if (existingUsers.length > 0) {
            const existing = existingUsers[0];
            const userCheck = await db.promise().query(
                'SELECT username, email FROM users WHERE id = ?',
                [existing.id]
            );
            
            if (userCheck[0][0].username === username) {
                return res.status(400).json({ 
                    success: false, 
                    message: 'ឈ្មោះអ្នកប្រើប្រាស់នេះមានរួចហើយ' 
                });
            }
            if (userCheck[0][0].email === email) {
                return res.status(400).json({ 
                    success: false, 
                    message: 'អ៊ីមែលនេះមានរួចហើយ' 
                });
            }
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create user
        const [result] = await db.promise().query(
            'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
            [username, email, hashedPassword]
        );

        // Generate JWT
        const token = jwt.sign(
            { 
                id: result.insertId, 
                username, 
                email 
            }, 
            JWT_SECRET, 
            { expiresIn: '7d' }
        );

        res.status(201).json({
            success: true,
            message: 'បង្កើតគណនីដោយជោគជ័យ',
            token,
            user: {
                id: result.insertId,
                username,
                email,
                balance: 0.00
            }
        });

    } catch (error) {
        console.error('Register error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'មានបញ្ហាក្នុងការបង្កើតគណនី' 
        });
    }
});

// Login
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ 
                success: false, 
                message: 'សូមបញ្ចូលឈ្មោះអ្នកប្រើប្រាស់ និងលេខសម្ងាត់' 
            });
        }

        // Find user by username
        const [users] = await db.promise().query(
            'SELECT id, username, email, password, balance FROM users WHERE username = ?',
            [username]
        );

        if (users.length === 0) {
            return res.status(401).json({ 
                success: false, 
                message: 'ឈ្មោះអ្នកប្រើប្រាស់ ឬលេខសម្ងាត់មិនត្រឹមត្រូវ' 
            });
        }

        const user = users[0];

        // Compare password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ 
                success: false, 
                message: 'ឈ្មោះអ្នកប្រើប្រាស់ ឬលេខសម្ងាត់មិនត្រឹមត្រូវ' 
            });
        }

        // Update last_login
        await db.promise().query(
            'UPDATE users SET last_login = NOW() WHERE id = ?',
            [user.id]
        );

        // Generate JWT
        const token = jwt.sign(
            { 
                id: user.id, 
                username: user.username, 
                email: user.email 
            }, 
            JWT_SECRET, 
            { expiresIn: '7d' }
        );

        res.json({
            success: true,
            message: 'ចូលប្រើប្រាស់ដោយជោគជ័យ',
            token,
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                balance: parseFloat(user.balance)
            }
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'មានបញ្ហាក្នុងការចូលប្រើប្រាស់' 
        });
    }
});

// Get user by ID (with token verification)
app.get('/api/user/:id', verifyToken, async (req, res) => {
    try {
        const userId = req.params.id;

        // Check if requested user matches token user
        if (req.user.id != userId) {
            return res.status(403).json({ 
                success: false, 
                message: 'មិនមានសិទ្ធិចូលមើលទិន្នន័យនេះទេ' 
            });
        }

        const [users] = await db.promise().query(
            'SELECT id, username, email, balance, created_at, last_login FROM users WHERE id = ?',
            [userId]
        );

        if (users.length === 0) {
            return res.status(404).json({ 
                success: false, 
                message: 'រកមិនឃើញអ្នកប្រើប្រាស់' 
            });
        }

        const user = users[0];
        res.json({
            success: true,
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                balance: parseFloat(user.balance),
                created_at: user.created_at,
                last_login: user.last_login
            }
        });

    } catch (error) {
        console.error('Get user error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'មានបញ្ហាក្នុងការទាញយកទិន្នន័យ' 
        });
    }
});

// Middleware to verify JWT token
function verifyToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ 
            success: false, 
            message: 'មិនមានសិទ្ធិចូលប្រើប្រាស់' 
        });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ 
                success: false, 
                message: 'Token មិនត្រឹមត្រូវ ឬផុតកំណត់' 
            });
        }
        req.user = user;
        next();
    });
}

// Start server
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});