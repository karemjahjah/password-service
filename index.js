const express = require('express');
const cors = require('cors');
const crypto = require('crypto'); // TOKENS
const bcrypt = require('bcrypt'); 
const db = require('./db');       // DB connection

const app = express();

// Middleware to parse JSON and Form data
app.use(cors()); 
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// homepage testing
app.get('/', (req, res) => {
    res.send(`
        <h2>Login Page (Simulation)</h2>
        <p>Forgot your password? <a href="/forgot-password-form">Click here</a></p>
    `);
});

// FORGOT PASSWORD FORM
app.get('/forgot-password-form', (req, res) => {
    res.send(`
        <h2>Forgot Password</h2>
        <form action="/forgot-password" method="POST">
            <label>Enter your email:</label>
            <input type="email" name="email" required placeholder="test@example.com" />
            <button type="submit">Send Reset Link</button>
        </form>
    `);
});

// POST forgot password
app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;

    try {
        // bruger eksistere
        const userResult = await db.query('SELECT id FROM users WHERE email = $1', [email]);
        
        if (userResult.rows.length > 0) {
            const userId = userResult.rows[0].id;

            // token generation
            const resetToken = crypto.randomBytes(32).toString('hex');
            
            // hashing token
            const tokenHash = crypto.createHash('sha256').update(resetToken).digest('hex');
            
            // expiration 30 minutes
            const expiresAt = new Date(Date.now() + 30 * 60 * 1000); 

            // 5. save to Database
            await db.query(
                'INSERT INTO password_reset_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, $3)',
                [userId, tokenHash, expiresAt]
            );

            // 6. LOG THE LINK
            const resetLink = `http://localhost:3000/reset-password?token=${resetToken}`;
            console.log("\n========================================");
            console.log("TESTING MODE - HERE IS YOUR RESET LINK:");
            console.log(resetLink);
            console.log("========================================\n");
        }

    
        res.json({ message: 'If an account with that email exists, a reset link has been sent.' });

    } catch (err) {
        console.error(err);
        res.status(500).send('Server error');
    }
});

// verify token and get method  
app.get('/reset-password', async (req, res) => {
    const { token } = req.query; // Get token from URL

    try {
        // hash the incoming token to match the database
        const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
        
        // check validity
        const tokenResult = await db.query(
            'SELECT * FROM password_reset_tokens WHERE token_hash = $1 AND is_used = false AND expires_at > NOW()',
            [tokenHash]
        );

        if (tokenResult.rows.length === 0) {
            return res.send('<h1>Invalid or expired link.</h1>');
        }

        // Show the form (with hidden token input)
        res.send(`
            <h2>Set New Password</h2>
            <form action="/reset-password" method="POST">
                <input type="hidden" name="token" value="${token}" />
                <label>New Password:</label>
                <input type="password" name="password" required />
                <button type="submit">Reset Password</button>
            </form>
        `);

    } catch (err) {
        console.error(err);
        res.send('Error verifying token');
    }
});

// update password post
app.post('/reset-password', async (req, res) => {
    const { token, password } = req.body;

    try {
        const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
        
        // validate token again
        const tokenResult = await db.query(
            'SELECT * FROM password_reset_tokens WHERE token_hash = $1 AND is_used = false AND expires_at > NOW()',
            [tokenHash]
        );

        if (tokenResult.rows.length === 0) {
            return res.send('Invalid token.');
        }

        const dbToken = tokenResult.rows[0];

        // 2. Hash new pw
        const passwordHash = await bcrypt.hash(password, 10);

        // 3. update pw in db
        await db.query('UPDATE users SET password_hash = $1 WHERE id = $2', [passwordHash, dbToken.user_id]);

        // 4. token marked as used
        await db.query('UPDATE password_reset_tokens SET is_used = true WHERE id = $1', [dbToken.id]);

        res.send('<h1>Success! Password reset. You can now login.</h1>');

    } catch (err) {
        console.error(err);
        res.send('Error updating password');
    }
});

// Start Server
app.listen(3000, () => {
    console.log('Server running on http://localhost:3000');
});