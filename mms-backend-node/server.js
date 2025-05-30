const express = require('express');
const mysql = require('mysql2/promise');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const cors = require('cors');
const WebSocket = require('ws');
const Razorpay = require('razorpay');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const dotenv = require('dotenv');

dotenv.config();

const app = express();
app.use(cors({ origin: 'http://localhost:8080' }));
app.use(express.json());

const dbConfig = {
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || 'Pass@123',
    database: process.env.DB_NAME || 'mms_db'
};

const razorpay = new Razorpay({
    key_id: process.env.RAZORPAY_KEY_ID,
    key_secret: process.env.RAZORPAY_KEY_SECRET
});

const transporter = nodemailer.createTransport({
    host: 'smtp.ethereal.email',
    port: 587,
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

async function initializeDatabase() {
    const db = await mysql.createConnection(dbConfig);
    try {
        console.log('Initializing database...');
        await db.execute(`
            CREATE TABLE IF NOT EXISTS users (
                email VARCHAR(255) PRIMARY KEY,
                password VARCHAR(255) NOT NULL,
                role ENUM('user', 'admin', 'employee') NOT NULL,
                otp VARCHAR(6),
                otp_expiry DATETIME
            )
        `);
        await db.execute(`
            CREATE TABLE IF NOT EXISTS movies (
                movie_id INT AUTO_INCREMENT PRIMARY KEY,
                title VARCHAR(255) NOT NULL,
                genre VARCHAR(100),
                duration INT,
                rating VARCHAR(10),
                director VARCHAR(255),
                actors TEXT,
                price DECIMAL(10, 2),
                language VARCHAR(50),
                subtitle_language VARCHAR(50),
                show_time DATETIME,
                format VARCHAR(50),
                cinema VARCHAR(100),
                coming_soon BOOLEAN DEFAULT FALSE,
                poster VARCHAR(255)
            )
        `);
        await db.execute(`
            CREATE TABLE IF NOT EXISTS screens (
                screen_id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(100) NOT NULL,
                total_seats INT NOT NULL
            )
        `);
        await db.execute(`
            CREATE TABLE IF NOT EXISTS screenings (
                screening_id INT AUTO_INCREMENT PRIMARY KEY,
                movie_id INT,
                screen_id INT,
                start_time DATETIME NOT NULL,
                end_time DATETIME NOT NULL,
                FOREIGN KEY (movie_id) REFERENCES movies(movie_id),
                FOREIGN KEY (screen_id) REFERENCES screens(screen_id)
            )
        `);
        await db.execute(`
            CREATE TABLE IF NOT EXISTS bookings (
                booking_id INT AUTO_INCREMENT PRIMARY KEY,
                user_email VARCHAR(255),
                screening_id INT,
                seats_booked INT NOT NULL,
                total_amount DECIMAL(10, 2) NOT NULL,
                payment_status ENUM('pending', 'completed', 'failed') DEFAULT 'pending',
                razorpay_order_id VARCHAR(255),
                booking_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_email) REFERENCES users(email),
                FOREIGN KEY (screening_id) REFERENCES screenings(screening_id)
            )
        `);
        await db.execute(`
            CREATE TABLE IF NOT EXISTS employees (
                employee_id INT AUTO_INCREMENT PRIMARY KEY,
                email VARCHAR(255) UNIQUE,
                name VARCHAR(255) NOT NULL,
                role VARCHAR(100),
                FOREIGN KEY (email) REFERENCES users(email)
            )
        `);
        console.log('Database initialized successfully');
    } catch (error) {
        console.error('Error initializing database:', error);
        throw error;
    } finally {
        await db.end();
    }
}

initializeDatabase().catch(console.error);

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) {
        console.log('Access denied: No token provided');
        return res.status(401).json({ error: 'Access denied: No token provided' });
    }

    jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret', (err, user) => {
        if (err) {
            console.log('Invalid token:', err.message);
            return res.status(403).json({ error: 'Invalid token' });
        }
        req.user = user;
        next();
    });
}

app.post('/signup', async (req, res) => {
    const { email, password, role } = req.body;
    if (!email || !password || !['user', 'employee'].includes(role)) {
        console.log('Invalid input data:', { email, role });
        return res.status(400).json({ error: 'Invalid input data' });
    }
    try {
        const db = await mysql.createConnection(dbConfig);
        const [existing] = await db.execute('SELECT email FROM users WHERE email = ?', [email]);
        if (existing.length > 0) {
            console.log('User already exists:', email);
            return res.status(409).json({ error: 'User already exists' });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const otp = crypto.randomInt(100000, 999999).toString();
        const otpExpiry = new Date(Date.now() + 10 * 60 * 1000);

        await db.execute(
            'INSERT INTO users (email, password, role, otp, otp_expiry) VALUES (?, ?, ?, ?, ?)',
            [email, hashedPassword, role, otp, otpExpiry]
        );

        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Your OTP for MMS Signup',
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2>Welcome to MMS</h2>
                    <p>Your OTP for signup is <strong>${otp}</strong>. It expires in 10 minutes.</p>
                    <p>If you did not request this, please ignore this email.</p>
                    <p>Best regards,<br>MMS Team</p>
                </div>
            `
        });

        console.log('OTP sent to email:', email);
        res.status(200).json({ message: 'OTP sent to email' });
        await db.end();
    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({ error: 'Error during signup' });
    }
});

app.post('/verify-otp', async (req, res) => {
    const { email, otp } = req.body;
    if (!email || !otp) {
        console.log('Email and OTP are required:', { email, otp });
        return res.status(400).json({ error: 'Email and OTP are required' });
    }
    try {
        const db = await mysql.createConnection(dbConfig);
        const [rows] = await db.execute(
            'SELECT otp, otp_expiry, role FROM users WHERE email = ?',
            [email]
        );

        if (rows.length === 0) {
            console.log('User not found:', email);
            return res.status(404).json({ error: 'User not found' });
        }
        if (rows[0].otp !== otp || new Date() > new Date(rows[0].otp_expiry)) {
            console.log('Invalid or expired OTP for:', email);
            return res.status(400).json({ error: 'Invalid or expired OTP' });
        }

        await db.execute('UPDATE users SET otp = NULL, otp_expiry = NULL WHERE email = ?', [email]);
        const token = jwt.sign({ email, role: rows[0].role }, process.env.JWT_SECRET || 'your_jwt_secret', { expiresIn: '1h' });
        console.log('OTP verified, token issued for:', email);
        res.status(200).json({ token });
        await db.end();
    } catch (error) {
        console.error('OTP verification error:', error);
        res.status(500).json({ error: 'Error verifying OTP' });
    }
});

app.post('/login', async (req, res) => {
    const { email, password, role } = req.body;
    if (!email || !password || !role) {
        console.log('Email, password, and role are required:', { email, role });
        return res.status(400).json({ error: 'Email, password, and role are required' });
    }
    try {
        const db = await mysql.createConnection(dbConfig);
        const [rows] = await db.execute(
            'SELECT password, role FROM users WHERE email = ?',
            [email]
        );

        if (rows.length === 0) {
            console.log('User not found:', email);
            return res.status(404).json({ error: 'User not found' });
        }
        if (!await bcrypt.compare(password, rows[0].password)) {
            console.log('Invalid password for:', email);
            return res.status(401).json({ error: 'Invalid password' });
        }
        if (rows[0].role !== role) {
            console.log('Invalid role for:', email, 'Expected:', role, 'Found:', rows[0].role);
            return res.status(403).json({ error: 'Invalid role' });
        }

        const token = jwt.sign({ email, role }, process.env.JWT_SECRET || 'your_jwt_secret', { expiresIn: '1h' });
        console.log('Login successful, token issued for:', email);
        res.status(200).json({ token });
        await db.end();
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Error during login' });
    }
});

app.get('/verify-token', authenticateToken, async (req, res) => {
    console.log('Token verified for:', req.user.email);
    res.status(200).json({ email: req.user.email, role: req.user.role });
});

app.get('/movies', authenticateToken, async (req, res) => {
    try {
        const db = await mysql.createConnection(dbConfig);
        const [rows] = await db.execute('SELECT * FROM movies');
        console.log('Movies fetched for user:', req.user.email, 'Count:', rows.length);
        res.status(200).json(rows);
        await db.end();
    } catch (error) {
        console.error('Error fetching movies:', error);
        res.status(500).json({ error: 'Error fetching movies' });
    }
});

app.post('/create-order', authenticateToken, async (req, res) => {
    const { amount, user, movie_id } = req.body;
    if (!amount || !user || !movie_id) {
        console.log('Amount, user, and movie_id are required:', { amount, user, movie_id });
        return res.status(400).json({ error: 'Amount, user, and movie_id are required' });
    }
    try {
        const db = await mysql.createConnection(dbConfig);
        const [screenings] = await db.execute(
            `SELECT screening_id FROM screenings WHERE movie_id = ? LIMIT 1`,
            [movie_id]
        );
        if (screenings.length === 0) {
            console.log('No screenings available for movie_id:', movie_id);
            return res.status(404).json({ error: 'No screenings available for this movie' });
        }

        const order = await razorpay.orders.create({
            amount: Math.round((amount + amount * 0.18) * 100), // 18% GST
            currency: 'INR',
            receipt: `receipt_${user}_${Date.now()}`
        });

        console.log('Order created for user:', user, 'Order ID:', order.id);
        res.status(200).json({
            key: process.env.RAZORPAY_KEY_ID,
            order_id: order.id,
            amount: amount + amount * 0.18,
            currency: 'INR'
        });
        await db.end();
    } catch (error) {
        console.error('Error creating order:', error);
        res.status(500).json({ error: 'Error creating order' });
    }
});

app.post('/book-ticket', authenticateToken, async (req, res) => {
    const { user, movie_id, payment_id } = req.body;
    const seats_booked = 1;
    if (!user || !movie_id || !payment_id) {
        console.log('User, movie_id, and payment_id are required:', { user, movie_id, payment_id });
        return res.status(400).json({ error: 'User, movie_id, and payment_id are required' });
    }
    try {
        const db = await mysql.createConnection(dbConfig);
        const [screenings] = await db.execute(
            `SELECT screening_id FROM screenings WHERE movie_id = ? LIMIT 1`,
            [movie_id]
        );
        if (screenings.length === 0) {
            console.log('No screenings available for movie_id:', movie_id);
            return res.status(404).json({ error: 'No screenings available' });
        }

        const screening_id = screenings[0].screening_id;
        const base_amount = 250;
        const total_amount = base_amount + base_amount * 0.18; // 18% GST

        const [movies] = await db.execute('SELECT title FROM movies WHERE movie_id = ?', [movie_id]);
        if (movies.length === 0) {
            console.log('Movie not found for movie_id:', movie_id);
            return res.status(404).json({ error: 'Movie not found' });
        }

        await db.execute(
            `INSERT INTO bookings (user_email, screening_id, seats_booked, total_amount, payment_status, razorpay_order_id) 
             VALUES (?, ?, ?, ?, ?, ?)`,
            [user, screening_id, seats_booked, total_amount, 'completed', payment_id]
        );

        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: user,
            subject: 'Ticket Booking Confirmation - MMS',
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2>Booking Confirmation</h2>
                    <p>Dear Customer,</p>
                    <p>Your ticket for <strong>${movies[0].title}</strong> has been booked successfully.</p>
                    <p><strong>Payment ID:</strong> ${payment_id}</p>
                    <p><strong>Total Amount:</strong> ₹${total_amount}</p>
                    <p>Thank you for choosing MMS. Enjoy your movie!</p>
                    <p>Best regards,<br>MMS Team</p>
                </div>
            `
        });

        console.log('Ticket booked successfully for user:', user, 'Movie:', movies[0].title);
        res.status(200).json({ message: 'Ticket booked successfully' });
        await db.end();
    } catch (error) {
        console.error('Error booking ticket:', error);
        res.status(500).json({ error: 'Error booking ticket' });
    }
});

app.post('/cancel-ticket', authenticateToken, async (req, res) => {
    const { booking_id } = req.body;
    if (!booking_id) {
        console.log('Booking ID is required:', { booking_id });
        return res.status(400).json({ error: 'Booking ID is required' });
    }
    try {
        const db = await mysql.createConnection(dbConfig);
        const [bookings] = await db.execute(
            `SELECT razorpay_order_id, total_amount FROM bookings WHERE booking_id = ? AND user_email = ?`,
            [booking_id, req.user.email]
        );
        if (bookings.length === 0) {
            console.log('Booking not found for user:', req.user.email, 'Booking ID:', booking_id);
            return res.status(404).json({ error: 'Booking not found' });
        }

        await db.execute(
            `UPDATE bookings SET payment_status = 'failed' WHERE booking_id = ?`,
            [booking_id]
        );

        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: req.user.email,
            subject: 'Ticket Cancellation Confirmation - MMS',
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2>Ticket Cancellation Confirmation</h2>
                    <p>Dear Customer,</p>
                    <p>Your ticket (Booking ID: <strong>${booking_id}</strong>) has been cancelled.</p>
                    <p>Refund will be processed soon to your original payment method.</p>
                    <p>If you have any questions, feel free to contact us at support@mms.com.</p>
                    <p>Best regards,<br>MMS Team</p>
                </div>
            `
        });

        console.log('Ticket cancelled for user:', req.user.email, 'Booking ID:', booking_id);
        res.status(200).json({ message: 'Ticket cancelled successfully' });
        await db.end();
    } catch (error) {
        console.error('Error cancelling ticket:', error);
        res.status(500).json({ error: 'Error cancelling ticket' });
    }
});

app.get('/reports', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') {
        console.log('Admin access required for reports, user:', req.user.email);
        return res.status(403).json({ error: 'Admin access required' });
    }
    try {
        const db = await mysql.createConnection(dbConfig);
        const [rows] = await db.execute(`
            SELECT m.title, COUNT(b.booking_id) as bookings, SUM(b.total_amount) as revenue
            FROM bookings b
            JOIN screenings s ON b.screening_id = s.screening_id
            JOIN movies m ON s.movie_id = m.movie_id
            GROUP BY m.movie_id
        `);
        console.log('Reports generated for admin:', req.user.email);
        res.status(200).json(rows);
        await db.end();
    } catch (error) {
        console.error('Error generating report:', error);
        res.status(500).json({ error: 'Error generating report' });
    }
});

app.post('/send-promo', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') {
        console.log('Admin access required for sending promo, user:', req.user.email);
        return res.status(403).json({ error: 'Admin access required' });
    }
    const { email, message } = req.body;
    if (!email || !message) {
        console.log('Email and message are required for promo:', { email });
        return res.status(400).json({ error: 'Email and message are required' });
    }
    try {
        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'New Movie Promotion - MMS',
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2>Movie Promotion</h2>
                    <p>${message}</p>
                    <p>Visit our website to book your tickets now!</p>
                    <p>Best regards,<br>MMS Team</p>
                </div>
            `
        });
        console.log('Promotion sent to:', email);
        res.status(200).json({ message: 'Promotion sent' });
    } catch (error) {
        console.error('Error sending promotion:', error);
        res.status(500).json({ error: 'Error sending promotion' });
    }
});

app.post('/schedule-screening', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') {
        console.log('Admin access required for scheduling screening, user:', req.user.email);
        return res.status(403).json({ error: 'Admin access required' });
    }
    const { movie_id, screen_id, start_time, end_time } = req.body;
    if (!movie_id || !screen_id || !start_time || !end_time) {
        console.log('All fields are required for scheduling screening:', { movie_id, screen_id });
        return res.status(400).json({ error: 'All fields are required' });
    }
    try {
        const db = await mysql.createConnection(dbConfig);
        await db.execute(
            `INSERT INTO screenings (movie_id, screen_id, start_time, end_time) VALUES (?, ?, ?, ?)`,
            [movie_id, screen_id, start_time, end_time]
        );
        console.log('Screening scheduled by admin:', req.user.email, 'Movie ID:', movie_id);
        res.status(200).json({ message: 'Screening scheduled' });
        await db.end();
    } catch (error) {
        console.error('Error scheduling screening:', error);
        res.status(500).json({ error: 'Error scheduling screening' });
    }
});

app.get('/bookings/stats', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') {
        console.log('Admin access required for booking stats, user:', req.user.email);
        return res.status(403).json({ error: 'Admin access required' });
    }
    try {
        const db = await mysql.createConnection(dbConfig);
        const [rows] = await db.execute(`
            SELECT m.title AS movie_title, COUNT(b.booking_id) AS tickets
            FROM bookings b
            JOIN screenings s ON b.screening_id = s.screening_id
            JOIN movies m ON s.movie_id = m.movie_id
            GROUP BY m.movie_id
        `);
        console.log('Booking stats fetched for admin:', req.user.email);
        res.status(200).json(rows);
        await db.end();
    } catch (error) {
        console.error('Error fetching booking stats:', error);
        res.status(500).json({ error: 'Error fetching booking stats' });
    }
});

app.post('/screenings', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') {
        console.log('Admin access required for adding screenings, user:', req.user.email);
        return res.status(403).json({ error: 'Admin access required' });
    }
    const { movie_id, screen, time } = req.body;
    if (!movie_id || !screen || !time) {
        console.log('Movie ID, screen, and time are required:', { movie_id, screen });
        return res.status(400).json({ error: 'Movie ID, screen, and time are required' });
    }
    try {
        const db = await mysql.createConnection(dbConfig);
        const [screens] = await db.execute('SELECT screen_id FROM screens WHERE name = ?', [screen]);
        if (screens.length === 0) {
            console.log('Screen not found:', screen);
            return res.status(404).json({ error: 'Screen not found' });
        }

        const screen_id = screens[0].screen_id;
        const start_time = new Date(time);
        const [movies] = await db.execute('SELECT duration FROM movies WHERE movie_id = ?', [movie_id]);
        if (movies.length === 0) {
            console.log('Movie not found for movie_id:', movie_id);
            return res.status(404).json({ error: 'Movie not found' });
        }

        const end_time = new Date(start_time.getTime() + movies[0].duration * 60000);

        await db.execute(
            'INSERT INTO screenings (movie_id, screen_id, start_time, end_time) VALUES (?, ?, ?, ?)',
            [movie_id, screen_id, start_time, end_time]
        );
        console.log('Screening added by admin:', req.user.email, 'Movie ID:', movie_id);
        res.status(200).json({ message: 'Screening added' });
        await db.end();
    } catch (error) {
        console.error('Error adding screening:', error);
        res.status(500).json({ error: 'Error adding screening' });
    }
});

app.post('/promotions', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') {
        console.log('Admin access required for sending promotions, user:', req.user.email);
        return res.status(403).json({ error: 'Admin access required' });
    }
    const { subject, message } = req.body;
    if (!subject || !message) {
        console.log('Subject and message are required for promotions');
        return res.status(400).json({ error: 'Subject and message are required' });
    }
    try {
        const db = await mysql.createConnection(dbConfig);
        const [users] = await db.execute('SELECT email FROM users WHERE role = "user"');
        const recipients = users.map(user => user.email).join(',');

        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: recipients,
            subject,
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2>${subject}</h2>
                    <p>${message}</p>
                    <p>Visit our website to book your tickets now!</p>
                    <p>Best regards,<br>MMS Team</p>
                </div>
            `
        });
        console.log('Promotion sent to users by admin:', req.user.email);
        res.status(200).json({ message: 'Promotion sent' });
        await db.end();
    } catch (error) {
        console.error('Error sending promotion:', error);
        res.status(500).json({ error: 'Error sending promotion' });
    }
});

app.get('/screenings', authenticateToken, async (req, res) => {
    const { movie_id } = req.query;
    try {
        const db = await mysql.createConnection(dbConfig);
        const query = movie_id
            ? `SELECT s.*, m.title, sc.name AS screen_name 
               FROM screenings s 
               JOIN movies m ON s.movie_id = m.movie_id 
               JOIN screens sc ON s.screen_id = sc.screen_id 
               WHERE s.movie_id = ?`
            : `SELECT s.*, m.title, sc.name AS screen_name 
               FROM screenings s 
               JOIN movies m ON s.movie_id = m.movie_id 
               JOIN screens sc ON s.screen_id = sc.screen_id`;
        const params = movie_id ? [movie_id] : [];
        const [rows] = await db.execute(query, params);
        console.log('Screenings fetched for user:', req.user.email, 'Movie ID:', movie_id || 'All');
        res.status(200).json(rows);
        await db.end();
    } catch (error) {
        console.error('Error fetching screenings:', error);
        res.status(500).json({ error: 'Error fetching screenings' });
    }
});

app.get('/bookings', authenticateToken, async (req, res) => {
    try {
        const db = await mysql.createConnection(dbConfig);
        const [rows] = await db.execute(`
            SELECT b.*, m.title AS movie_title, s.start_time
            FROM bookings b
            JOIN screenings s ON b.screening_id = s.screening_id
            JOIN movies m ON s.movie_id = m.movie_id
            WHERE b.user_email = ?
        `, [req.user.email]);
        console.log('Bookings fetched for user:', req.user.email, 'Count:', rows.length);
        res.status(200).json(rows);
        await db.end();
    } catch (error) {
        console.error('Error fetching bookings:', error);
        res.status(500).json({ error: 'Error fetching bookings' });
    }
});

const server = app.listen(3000, () => console.log('Server running on port 3000'));
const wss = new WebSocket.Server({ server });

wss.on('connection', (ws, req) => {
    const token = new URLSearchParams(req.url.split('?')[1]).get('token');
    if (!token) {
        console.log('WebSocket connection rejected: No token provided');
        ws.close();
        return;
    }

    jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret', async (err, user) => {
        if (err) {
            console.log('WebSocket connection rejected: Invalid token');
            ws.close();
            return;
        }

        console.log('WebSocket connection established for user:', user.email);

        // Set a timeout for inactive WebSocket clients
        const timeout = setTimeout(() => {
            console.log('WebSocket connection timed out for user:', user.email);
            ws.close();
        }, 5 * 60 * 1000); // 5 minutes timeout

        ws.on('message', async (message) => {
            try {
                const { type } = JSON.parse(message);
                if (type === 'getScreenings') {
                    const db = await mysql.createConnection(dbConfig);
                    const [rows] = await db.execute(`
                        SELECT s.screening_id, m.title, s.screen_id, sc.name AS screen_name, s.start_time, s.end_time
                        FROM screenings s
                        JOIN movies m ON s.movie_id = m.movie_id
                        JOIN screens sc ON s.screen_id = sc.screen_id
                    `);
                    ws.send(JSON.stringify({ type: 'screenings', data: rows }));
                    await db.end();
                    console.log('Screenings sent via WebSocket to user:', user.email);
                }
            } catch (error) {
                console.error('WebSocket error:', error);
                ws.send(JSON.stringify({ type: 'error', message: 'Error processing request' }));
            }
        });

        const interval = setInterval(async () => {
            try {
                const db = await mysql.createConnection(dbConfig);
                const [rows] = await db.execute(`
                    SELECT s.screening_id, m.title, s.screen_id, sc.name AS screen_name, s.start_time, s.end_time
                    FROM screenings s
                    JOIN movies m ON s.movie_id = m.movie_id
                    JOIN screens sc ON s.screen_id = sc.screen_id
                `);
                ws.send(JSON.stringify({ type: 'screenings', data: rows }));
                await db.end();
                console.log('Periodic screenings update sent via WebSocket to user:', user.email);
            } catch (error) {
                console.error('WebSocket periodic update error:', error);
            }
        }, 60000);

        ws.on('close', () => {
            clearInterval(interval);
            clearTimeout(timeout);
            console.log('WebSocket connection closed for user:', user.email);
        });
    });
});