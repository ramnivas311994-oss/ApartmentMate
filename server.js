// ApartMate Backend Server
// Node.js + Express + PostgreSQL
// Complete API Implementation Example

const express = require('express');
const pg = require('pg');
const bcryptjs = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const dotenv = require('dotenv');
const axios = require('axios');
const admin = require('firebase-admin');
const Razorpay = require('razorpay');

// Configuration
dotenv.config();
const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Database Pool
const pool = new pg.Pool({
    host: process.env.DB_HOST || 'localhost',
    port: process.env.DB_PORT || 5432,
    database: process.env.DB_NAME || 'apartmate_db',
    user: process.env.DB_USER || 'postgres',
    password: process.env.DB_PASSWORD,
});

// Firebase Admin Setup
admin.initializeApp({
    credential: admin.credential.cert(JSON.parse(process.env.FIREBASE_ADMIN_KEY)),
});

// Razorpay Setup
const razorpay = new Razorpay({
    key_id: process.env.RAZORPAY_KEY_ID,
    key_secret: process.env.RAZORPAY_KEY_SECRET,
});

// ============================================================
// AUTHENTICATION MIDDLEWARE
// ============================================================

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.sendStatus(401);

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// ============================================================
// AUTHENTICATION ROUTES
// ============================================================

// Register
app.post('/api/auth/register', async (req, res) => {
    try {
        const { email, password, full_name, role } = req.body;

        // Validate input
        if (!email || !password || !full_name) {
            return res.status(400).json({ error: 'Missing required fields' });
        }

        // Hash password
        const hashedPassword = await bcryptjs.hash(password, 10);

        // Insert user
        const result = await pool.query(
            'INSERT INTO users (email, password, role, full_name) VALUES ($1, $2, $3, $4) RETURNING id, email, role',
            [email, hashedPassword, role || 'resident', full_name]
        );

        res.json({
            success: true,
            user: result.rows[0],
            message: 'User registered successfully',
        });
    } catch (error) {
        console.error('Register error:', error);
        res.status(500).json({ error: 'Registration failed', details: error.message });
    }
});

// Login
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password required' });
        }

        // Get user
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        const user = result.rows[0];

        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Verify password
        const validPassword = await bcryptjs.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Generate JWT
        const token = jwt.sign(
            { id: user.id, email: user.email, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        // Update last login
        await pool.query('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = $1', [user.id]);

        res.json({
            success: true,
            token,
            user: { id: user.id, email: user.email, role: user.role, full_name: user.full_name },
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// ============================================================
// APARTMENT ROUTES
// ============================================================

// Get all apartments (with pagination)
app.get('/api/apartments', authenticateToken, async (req, res) => {
    try {
        const { page = 1, limit = 20, search = '' } = req.query;
        const offset = (page - 1) * limit;

        let query = 'SELECT * FROM apartments WHERE unit_number ILIKE $1 OR resident_name ILIKE $1';
        let countQuery = 'SELECT COUNT(*) FROM apartments WHERE unit_number ILIKE $1 OR resident_name ILIKE $1';
        const searchParam = `%${search}%`;

        // Add building filter for managers
        if (req.user.role === 'building_manager') {
            query += ' AND building_id = $2';
            countQuery += ' AND building_id = $2';
        }

        query += ` ORDER BY unit_number ASC LIMIT $${req.user.role === 'building_manager' ? 3 : 2} OFFSET $${req.user.role === 'building_manager' ? 4 : 3}`;

        const params = req.user.role === 'building_manager'
            ? [searchParam, req.user.building_id, limit, offset]
            : [searchParam, limit, offset];

        const [apartments, countResult] = await Promise.all([
            pool.query(query, params),
            pool.query(countQuery, [searchParam]),
        ]);

        res.json({
            success: true,
            data: apartments.rows,
            pagination: {
                page: parseInt(page),
                limit: parseInt(limit),
                total: parseInt(countResult.rows[0].count),
                pages: Math.ceil(countResult.rows[0].count / limit),
            },
        });
    } catch (error) {
        console.error('Get apartments error:', error);
        res.status(500).json({ error: 'Failed to fetch apartments' });
    }
});

// Get apartment by ID
app.get('/api/apartments/:id', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM apartments WHERE id = $1',
            [req.params.id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Apartment not found' });
        }

        res.json({ success: true, data: result.rows[0] });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch apartment' });
    }
});

// Create apartment
app.post('/api/apartments', authenticateToken, async (req, res) => {
    try {
        const { building_id, unit_number, resident_name, resident_phone, resident_email } = req.body;

        const result = await pool.query(
            'INSERT INTO apartments (building_id, unit_number, resident_name, resident_phone, resident_email) VALUES ($1, $2, $3, $4, $5) RETURNING *',
            [building_id, unit_number, resident_name, resident_phone, resident_email]
        );

        res.json({
            success: true,
            data: result.rows[0],
            message: 'Apartment created successfully',
        });
    } catch (error) {
        console.error('Create apartment error:', error);
        res.status(500).json({ error: 'Failed to create apartment', details: error.message });
    }
});

// ============================================================
// BILLS ROUTES
// ============================================================

// Get bills with filters
app.get('/api/bills', authenticateToken, async (req, res) => {
    try {
        const { month, status, apartment_id, page = 1, limit = 20 } = req.query;
        const offset = (page - 1) * limit;

        let query = 'SELECT b.*, a.unit_number, a.resident_name FROM bills b JOIN apartments a ON b.apartment_id = a.id WHERE 1=1';
        const params = [];
        let paramCount = 1;

        if (month) {
            query += ` AND b.bill_month = $${paramCount}`;
            params.push(month);
            paramCount++;
        }

        if (status) {
            query += ` AND b.status = $${paramCount}`;
            params.push(status);
            paramCount++;
        }

        if (apartment_id) {
            query += ` AND b.apartment_id = $${paramCount}`;
            params.push(apartment_id);
            paramCount++;
        }

        query += ` ORDER BY b.due_date DESC LIMIT $${paramCount} OFFSET $${paramCount + 1}`;
        params.push(limit, offset);

        const result = await pool.query(query, params);

        res.json({
            success: true,
            data: result.rows,
            pagination: { page: parseInt(page), limit: parseInt(limit) },
        });
    } catch (error) {
        console.error('Get bills error:', error);
        res.status(500).json({ error: 'Failed to fetch bills' });
    }
});

// Create bill (bulk insert for building)
app.post('/api/bills', authenticateToken, async (req, res) => {
    try {
        const { building_id, bill_month, amount, due_date, description } = req.body;

        // Get all apartments in building
        const apartments = await pool.query(
            'SELECT id FROM apartments WHERE building_id = $1 AND is_occupied = true',
            [building_id]
        );

        const bills = [];
        for (const apt of apartments.rows) {
            const result = await pool.query(
                'INSERT INTO bills (building_id, apartment_id, bill_month, amount, due_date, status, description, created_by) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *',
                [building_id, apt.id, bill_month, amount, due_date, 'pending', description, req.user.id]
            );
            bills.push(result.rows[0]);
        }

        res.json({
            success: true,
            data: bills,
            message: `${bills.length} bills created successfully`,
        });
    } catch (error) {
        console.error('Create bill error:', error);
        res.status(500).json({ error: 'Failed to create bills' });
    }
});

// ============================================================
// PAYMENT ROUTES
// ============================================================

// Create payment link
app.post('/api/payments/create-link', authenticateToken, async (req, res) => {
    try {
        const { bill_id } = req.body;

        // Get bill details
        const billResult = await pool.query(
            'SELECT b.*, a.unit_number, a.resident_name, a.resident_phone FROM bills b JOIN apartments a ON b.apartment_id = a.id WHERE b.id = $1',
            [bill_id]
        );

        if (billResult.rows.length === 0) {
            return res.status(404).json({ error: 'Bill not found' });
        }

        const bill = billResult.rows[0];
        const token = Math.random().toString(36).slice(2, 10);
        const link = `${process.env.PAYMENT_DOMAIN || 'https://pay.apartmate.in'}/${bill.unit_number}?bill=${bill_id}&token=${token}`;

        // Save payment link
        const linkResult = await pool.query(
            'INSERT INTO payment_links (bill_id, apartment_id, token, link, status, expires_at) VALUES ($1, $2, $3, $4, $5, NOW() + INTERVAL \'30 days\') RETURNING *',
            [bill_id, bill.apartment_id, token, link, 'active']
        );

        res.json({
            success: true,
            data: {
                link: linkResult.rows[0].link,
                qr_code: `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(link)}`,
                unit: bill.unit_number,
                resident: bill.resident_name,
                amount: bill.amount,
            },
        });
    } catch (error) {
        console.error('Create payment link error:', error);
        res.status(500).json({ error: 'Failed to create payment link' });
    }
});

// Razorpay payment order
app.post('/api/payments/razorpay-order', authenticateToken, async (req, res) => {
    try {
        const { bill_id, amount } = req.body;

        const order = await razorpay.orders.create({
            amount: amount * 100, // Razorpay expects amount in paise
            currency: 'INR',
            receipt: `bill_${bill_id}`,
            notes: { bill_id },
        });

        res.json({
            success: true,
            order: order,
        });
    } catch (error) {
        console.error('Razorpay order error:', error);
        res.status(500).json({ error: 'Failed to create order' });
    }
});

// Payment webhook (Razorpay callback)
app.post('/api/payments/webhook', async (req, res) => {
    try {
        const { bill_id, amount, transaction_id, payment_method } = req.body;

        // Verify webhook signature (implement proper signature verification)
        
        // Update payment status
        const result = await pool.query(
            'INSERT INTO payments (bill_id, apartment_id, building_id, amount, payment_method, transaction_id, status, paid_at) SELECT $1, apartment_id, building_id, $2, $3, $4, $5, CURRENT_TIMESTAMP FROM bills WHERE id = $1 RETURNING *',
            [bill_id, amount, payment_method, transaction_id, 'completed']
        );

        // Update bill status
        await pool.query(
            'UPDATE bills SET status = $1 WHERE id = $2',
            ['paid', bill_id]
        );

        // Get payment details for notification
        const paymentData = result.rows[0];
        const billData = await pool.query('SELECT * FROM apartments WHERE id = $1', [paymentData.apartment_id]);

        // Send notifications
        await sendNotifications(paymentData.apartment_id, paymentData.building_id, 'payment_received', {
            amount: amount,
            unit: billData.rows[0].unit_number,
            transaction_id: transaction_id,
        });

        res.json({ success: true, message: 'Payment confirmed' });
    } catch (error) {
        console.error('Webhook error:', error);
        res.status(500).json({ error: 'Webhook processing failed' });
    }
});

// ============================================================
// NOTIFICATION ROUTES
// ============================================================

// Send payment link via WhatsApp
app.post('/api/notifications/send-whatsapp', authenticateToken, async (req, res) => {
    try {
        const { bill_id, phone } = req.body;

        const billResult = await pool.query(
            'SELECT b.*, a.unit_number, a.resident_name, l.link FROM bills b JOIN apartments a ON b.apartment_id = a.id LEFT JOIN payment_links l ON b.id = l.bill_id WHERE b.id = $1',
            [bill_id]
        );

        if (billResult.rows.length === 0) {
            return res.status(404).json({ error: 'Bill not found' });
        }

        const bill = billResult.rows[0];
        const message = `Dear ${bill.resident_name} (Flat ${bill.unit_number}) 🙏\n\nYour March 2025 maintenance of ₹${bill.amount} is due.\n\nPay here in 30 seconds 👉 ${bill.link}\n\nGPay · PhonePe · Paytm · Any UPI ✅`;

        // Send via WhatsApp API (implement WhatsApp Business API integration)
        // Example: https://wa.me/91{phone}?text={message}

        res.json({
            success: true,
            message: 'WhatsApp message sent',
            whatsapp_link: `https://wa.me/91${phone}?text=${encodeURIComponent(message)}`,
        });
    } catch (error) {
        console.error('WhatsApp error:', error);
        res.status(500).json({ error: 'Failed to send WhatsApp message' });
    }
});

// Send Firebase push notification
app.post('/api/notifications/send-push', authenticateToken, async (req, res) => {
    try {
        const { user_id, title, message, data } = req.body;

        // Get user FCM token from database
        const userResult = await pool.query(
            'SELECT fcm_token FROM users WHERE id = $1',
            [user_id]
        );

        if (userResult.rows.length === 0 || !userResult.rows[0].fcm_token) {
            return res.status(404).json({ error: 'FCM token not found' });
        }

        const fcmToken = userResult.rows[0].fcm_token;

        // Send Firebase notification
        const response = await admin.messaging().send({
            token: fcmToken,
            notification: { title, body: message },
            data: data || {},
        });

        // Log notification
        await pool.query(
            'INSERT INTO notifications (user_id, notification_type, title, message, channel, send_status, sent_at) VALUES ($1, $2, $3, $4, $5, $6, CURRENT_TIMESTAMP)',
            [user_id, 'push', title, message, 'push', 'sent']
        );

        res.json({
            success: true,
            message: 'Notification sent',
            response: response,
        });
    } catch (error) {
        console.error('Push notification error:', error);
        res.status(500).json({ error: 'Failed to send notification' });
    }
});

// ============================================================
// DASHBOARD ROUTES
// ============================================================

// Dashboard statistics
app.get('/api/dashboard/stats', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM v_dashboard_summary WHERE building_id = $1', [req.user.building_id || 1]);

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Building not found' });
        }

        const stats = result.rows[0];

        res.json({
            success: true,
            data: {
                total_apartments: stats.total_apartments,
                occupied_units: stats.occupied_units,
                total_collected: stats.total_collected || 0,
                total_pending: stats.total_pending || 0,
                total_overdue: stats.total_overdue || 0,
                collection_percentage: stats.total_apartments ? Math.round((stats.paid_count / stats.total_apartments) * 100) : 0,
            },
        });
    } catch (error) {
        console.error('Dashboard stats error:', error);
        res.status(500).json({ error: 'Failed to fetch dashboard stats' });
    }
});

// ============================================================
// HELPER FUNCTIONS
// ============================================================

async function sendNotifications(apartmentId, buildingId, type, data) {
    try {
        // Insert notification log
        const notification = await pool.query(
            'INSERT INTO notifications (building_id, apartment_id, notification_type, title, message, send_status) VALUES ($1, $2, $3, $4, $5, $6)',
            [
                buildingId,
                apartmentId,
                type,
                `Payment Notification: ${type}`,
                JSON.stringify(data),
                'pending',
            ]
        );

        // Send through different channels (email, SMS, push)
        // Implementation depends on your notification service
    } catch (error) {
        console.error('Send notifications error:', error);
    }
}

// ============================================================
// ERROR HANDLING & SERVER START
// ============================================================

app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: 'Something went wrong', message: err.message });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 ApartMate API Server running on port ${PORT}`);
    console.log(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);
});

module.exports = app;
