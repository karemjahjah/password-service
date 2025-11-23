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
    const { token } = req.query; 

    try {
        const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
        
        const tokenResult = await db.query(
            'SELECT * FROM password_reset_tokens WHERE token_hash = $1 AND is_used = false AND expires_at > NOW()',
            [tokenHash]
        );

        if (tokenResult.rows.length === 0) {
            // RETURN JSON ERROR
            return res.status(400).json({ valid: false, message: 'Invalid or expired link.' });
        }

        // RETURN JSON SUCCESS 
        res.json({ valid: true, message: 'Token is valid.' });

    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error' });
    }
});

// update password post
app.post('/reset-password', async (req, res) => {
    const { token, password } = req.body;

    try {
        const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
        
        const tokenResult = await db.query(
            'SELECT * FROM password_reset_tokens WHERE token_hash = $1 AND is_used = false AND expires_at > NOW()',
            [tokenHash]
        );

        if (tokenResult.rows.length === 0) {
            return res.status(400).json({ message: 'Invalid token.' });
        }

        const dbToken = tokenResult.rows[0];

        // Hash new pw
        const passwordHash = await bcrypt.hash(password, 10);

        // Update pw in db
        await db.query('UPDATE users SET password_hash = $1 WHERE id = $2', [passwordHash, dbToken.user_id]);

        // Token marked as used
        await db.query('UPDATE password_reset_tokens SET is_used = true WHERE id = $1', [dbToken.id]);

        // SEND JSON SUCCESS
        res.json({ success: true, message: 'Password successfully reset.' });

    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error updating password' });
    }
});

// port 3000 eller hvad end render giver
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});