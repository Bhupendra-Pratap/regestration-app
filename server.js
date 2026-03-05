require('dotenv').config(); // This loads your hidden .env variables!
const nodemailer = require('nodemailer');
const express = require('express');
const mongoose = require('mongoose');
const path = require('path');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const { OAuth2Client } = require('google-auth-library');

const app = express();
const PORT = 3000;

// Put your actual Google Client ID here
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// Middleware to parse JSON and serve your HTML file
app.use(express.json());
app.use(express.static('public'));

// 1. Connect to MongoDB Atlas 
mongoose.connect(process.env.MONGODB_URI)
    .then(() => console.log('✅ Connected to MongoDB Atlas'))
    .catch(err => console.error('❌ Database connection error:', err));

// 2. Define the Database Schema (Must match your form fields!)
const userSchema = new mongoose.Schema({
    firstname: { type: String, required: true },
    lastname: { type: String, required: true },
    phone: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    dob: { type: Date, required: true },
    gender: { type: String, required: true },
    password: { type: String, required: true },
    // NEW FIELDS FOR PASSWORD RESET:
    resetPasswordToken: { type: String },
    resetPasswordExpires: { type: Date }
});

// Create the model to interact with the "users" collection
const User = mongoose.model('User', userSchema,'users');

// ==========================================
// GOOGLE LOGIN/REGISTER ROUTE
// ==========================================
app.post('/google-login', async (req, res) => {
    try {
        const { token } = req.body;

        // 1. Verify the token with Google
        const ticket = await googleClient.verifyIdToken({
            idToken: token,
            audience: GOOGLE_CLIENT_ID
        });
        
        // 2. Extract the user's info from Google's verified ticket
        const payload = ticket.getPayload();
        const { email, given_name, family_name } = payload;

        // 3. Check if this user already exists in your MongoDB
        let user = await User.findOne({ email: email });

        if (!user) {
            // 4. If they don't exist, register them automatically!
            // (We generate a random secure password and dummy data for fields Google doesn't provide)
            const randomPassword = await bcrypt.hash(Math.random().toString(36).slice(-8), 10);
            
            user = new User({
                firstname: given_name,
                lastname: family_name || 'User',
                email: email,
                phone: '0000000000', // Dummy phone
                dob: new Date(),     // Dummy DOB
                gender: 'Not Specified',
                password: randomPassword
            });
            await user.save();
        }

        // 5. Send success back to the frontend
        res.status(200).json({ 
            message: 'Google Login successful', 
            firstname: user.firstname 
        });

    } catch (error) {
        console.error("Google Auth Error:", error);
        res.status(401).json({ error: 'Google verification failed' });
    }
});

// 3. Create the API Route to handle the form submission
app.post('/register', async (req, res) => {
    try {
        // 1. Extract the data from the request body
        const { firstname, lastname, phone, email, dob, gender, password } = req.body;

        // 2. Hash (scramble) the password
        const saltRounds = 10; // This dictates how complex the math is
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // 3. Create the new user, using the HASHED password instead of the plain one!
        const newUser = new User({
            firstname,
            lastname,
            phone,
            email,
            dob,
            gender,
            password: hashedPassword // <--- THE SECURE PART
        });
        
        // 4. Save to MongoDB
        await newUser.save();
        
        res.status(201).json({ message: 'User registered securely!' });
    } catch (error) {
        console.error("Error saving user:", error);
        if (error.code === 11000) {
            res.status(400).json({ error: 'Email already exists!' });
        } else {
            res.status(500).json({ error: 'Failed to register user.' });
        }
    }
});
// ==========================================
// LOGIN ROUTE
// ==========================================
app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // 1. Find the user by email
        const user = await User.findOne({ email: email });

        if (!user) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        // 2. 🚨 THE UPGRADE: Use bcrypt to compare the typed password with the hashed database password
        const isMatch = await bcrypt.compare(password, user.password);
        
        if (!isMatch) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        // 3. If we made it here, the passwords match!
        res.status(200).json({ 
            message: 'Login successful', 
            firstname: user.firstname 
        });

    } catch (error) {
        console.error("Login error:", error);
        res.status(500).json({ error: 'Server error' });
    }
});

// ==========================================
// FORGOT PASSWORD (Generate Token & Send REAL Email)
// ==========================================
app.post('/forgot-password', async (req, res) => {
    try {
        const user = await User.findOne({ email: req.body.email });
        if (!user) {
            return res.status(404).json({ error: 'No account with that email address exists.' });
        }

        // 1. Generate the random secure token
        const token = crypto.randomBytes(20).toString('hex');

        // 2. Save it to the database (expires in 1 hour)
        user.resetPasswordToken = token;
        user.resetPasswordExpires = Date.now() + 3600000; 
        await user.save();

        // 3. Create the reset link
        const resetLink = `http://localhost:3000/reset-password.html?token=${token}`;

        // 4. Configure Nodemailer with your Gmail credentials
        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: { 
                user: process.env.EMAIL_USER, // Grabs from .env
                pass: process.env.EMAIL_PASS  // Grabs from .env
            }
        });

        // 5. Build and send the actual email
        const mailOptions = {
            to: user.email,
            from: process.env.EMAIL_USER,
            subject: 'Password Reset Request - My App',
            html: `
                <h3>Hello ${user.firstname},</h3>
                <p>You requested a password reset for your account.</p>
                <p>Please click the link below to set a new password. This link will expire in 1 hour.</p>
                <a href="${resetLink}" style="padding: 10px 20px; background-color: #667eea; color: white; text-decoration: none; border-radius: 5px; display: inline-block;">Reset Password</a>
                <br><br>
                <p>If you did not request this, please ignore this email.</p>
            `
        };

        // Send it!
        await transporter.sendMail(mailOptions);
        
        console.log(`✅ Success! Reset email sent to ${user.email}`);
        res.status(200).json({ message: 'A reset link has been sent to your email!' });

    } catch (error) {
        console.error("Email sending error:", error);
        res.status(500).json({ error: 'Failed to send email. Check your server logs.' });
    }
});

// ==========================================
// 2. RESET PASSWORD (Save the new password)
// ==========================================
app.post('/reset-password', async (req, res) => {
    try {
        const { token, newPassword } = req.body;

        // Find user by token AND ensure the token hasn't expired ($gt means "greater than" current time)
        const user = await User.findOne({ 
            resetPasswordToken: token, 
            resetPasswordExpires: { $gt: Date.now() } 
        });

        if (!user) {
            return res.status(400).json({ error: 'Password reset token is invalid or has expired.' });
        }

        // Hash the new password
        user.password = await bcrypt.hash(newPassword, 10);
        
        // Clear the tokens so they can't be used again!
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;
        await user.save();

        res.status(200).json({ message: 'Success! Your password has been changed.' });

    } catch (error) {
        console.error("Reset password error:", error);
        res.status(500).json({ error: 'Server error' });
    }
});

// 4. Start the server
app.listen(PORT, () => {
    console.log(`🚀 Server running at http://localhost:${PORT}`);
});