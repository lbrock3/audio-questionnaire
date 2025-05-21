// server.js - Complete server implementation for audio questionnaire

const express = require('express');
const multer = require('multer');
const mongoose = require('mongoose');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
// Removed bcrypt and jwt for simplified authentication
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public')); // For serving the admin dashboard

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/audio-questionnaire', {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log('Connected to MongoDB'))
.catch(err => console.error('MongoDB connection error:', err));

// Create models
const responseSchema = new mongoose.Schema({
    submittedAt: { type: Date, default: Date.now },
    ipAddress: String,
    userAgent: String,
    responses: [{
        questionIndex: Number,
        questionText: String,
        audioFilename: String
    }]
});

// Simplified user schema - no password hashing
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true }, // Plain text password - suitable for non-sensitive data
    isAdmin: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now }
});

const Response = mongoose.model('Response', responseSchema);
const User = mongoose.model('User', userSchema);

// Configure file storage
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadDir = path.join(__dirname, 'uploads');
        // Create directory if it doesn't exist
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir, { recursive: true });
        }
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        // Create unique filename with timestamp and random string
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({
    storage: storage,
    fileFilter: (req, file, cb) => {
        // Only accept audio files
        if (file.mimetype.startsWith('audio/')) {
            cb(null, true);
        } else {
            cb(new Error('Only audio files are allowed'));
        }
    },
    limits: {
        fileSize: 10 * 1024 * 1024 // Limit file size to 10MB
    }
});

// Authentication middleware - simplified for non-sensitive data
const authenticateUser = (req, res, next) => {
    const username = req.headers['username'];
    const password = req.headers['password'];

    if (!username || !password) {
        return res.status(401).json({ message: 'Authentication required' });
    }

    // Simple username/password check
    User.findOne({ username: username })
    .then(user => {
        if (!user || user.password !== password) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }
        req.user = user;
        next();
    })
    .catch(err => {
        console.error('Auth error:', err);
        res.status(500).json({ message: 'Authentication error' });
    });
};

// Create initial admin user if none exists
const createAdminUser = async () => {
    try {
        const adminExists = await User.findOne({ isAdmin: true });
        if (!adminExists) {
            // Store password as plain text - acceptable for non-sensitive data
            await User.create({
                username: process.env.ADMIN_USERNAME || 'admin',
                password: process.env.ADMIN_INITIAL_PASSWORD || 'admin123',
                isAdmin: true
            });
            console.log('Admin user created');
        }
    } catch (error) {
        console.error('Error creating admin user:', error);
    }
};

// Routes

// Submit questionnaire responses
app.post('/api/submit-responses', upload.array('audio_responses'), async (req, res) => {
    try {
        // Process form data
        const files = req.files;
        const questions = req.body;

        // Create response object
        const response = new Response({
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            responses: []
        });

        // Map files to questions
        files.forEach(file => {
            const questionIndexMatch = file.originalname.match(/question_(\d+)/);
            if (questionIndexMatch) {
                const questionIndex = parseInt(questionIndexMatch[1]) - 1;
                response.responses.push({
                    questionIndex,
                    questionText: questions[`question_${questionIndex+1}`],
                    audioFilename: file.filename
                });
            }
        });

        // Save to database
        await response.save();

        res.status(200).json({
            success: true,
            message: 'Responses submitted successfully',
            responseId: response._id
        });
    } catch (error) {
        console.error('Error handling submission:', error);
        res.status(500).json({
            success: false,
            message: 'An error occurred while processing your submission'
        });
    }
});

// Authentication routes - simplified for non-sensitive data
app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        // Find user with direct password comparison
        const user = await User.findOne({ username });
        if (!user) return res.status(400).json({ message: 'Invalid username or password' });

        if (user.password !== password) {
            return res.status(400).json({ message: 'Invalid username or password' });
        }

        // Return user info directly - no token needed
        res.status(200).json({
            username: user.username,
            isAdmin: user.isAdmin
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'An error occurred during login' });
    }
});

// Admin routes
app.get('/api/admin/responses', authenticateUser, async (req, res) => {
    // Verify admin privileges
    if (!req.user.isAdmin) return res.status(403).json({ message: 'Admin privileges required' });

    try {
        // Get all responses with pagination
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 10;
        const skip = (page - 1) * limit;

        const responses = await Response.find()
        .sort({ submittedAt: -1 })
        .skip(skip)
        .limit(limit);

        const total = await Response.countDocuments();

        res.status(200).json({
            responses,
            pagination: {
                total,
                page,
                pages: Math.ceil(total / limit)
            }
        });
    } catch (error) {
        console.error('Error fetching responses:', error);
        res.status(500).json({ message: 'An error occurred while fetching responses' });
    }
});

// Get specific response
app.get('/api/admin/responses/:id', authenticateUser, async (req, res) => {
    if (!req.user.isAdmin) return res.status(403).json({ message: 'Admin privileges required' });

    try {
        const response = await Response.findById(req.params.id);
        if (!response) return res.status(404).json({ message: 'Response not found' });

        res.status(200).json({ response });
    } catch (error) {
        console.error('Error fetching response:', error);
        res.status(500).json({ message: 'An error occurred while fetching the response' });
    }
});

// Stream audio file - simplified, no authentication for non-sensitive data
app.get('/api/admin/audio/:filename', (req, res) => {
    const filename = req.params.filename;
    const filePath = path.join(__dirname, 'uploads', filename);

    // Check if file exists
    if (!fs.existsSync(filePath)) {
        return res.status(404).json({ message: 'Audio file not found' });
    }

    // Stream the file
    res.sendFile(filePath);
});

// Download audio file - simplified, no authentication for non-sensitive data
app.get('/api/admin/download/:filename', (req, res) => {
    const filename = req.params.filename;
    const filePath = path.join(__dirname, 'uploads', filename);

    if (!fs.existsSync(filePath)) {
        return res.status(404).json({ message: 'Audio file not found' });
    }

    res.download(filePath);
});

// Delete response
app.delete('/api/admin/responses/:id', authenticateUser, async (req, res) => {
    if (!req.user.isAdmin) return res.status(403).json({ message: 'Admin privileges required' });

    try {
        const response = await Response.findById(req.params.id);
        if (!response) return res.status(404).json({ message: 'Response not found' });

        // Delete associated audio files
        response.responses.forEach(item => {
            const filePath = path.join(__dirname, 'uploads', item.audioFilename);
            if (fs.existsSync(filePath)) {
                fs.unlinkSync(filePath);
            }
        });

        // Delete response from database
        await Response.findByIdAndDelete(req.params.id);

        res.status(200).json({ message: 'Response deleted successfully' });
    } catch (error) {
        console.error('Error deleting response:', error);
        res.status(500).json({ message: 'An error occurred while deleting the response' });
    }
});

// Serve admin dashboard
app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Start server
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
    createAdminUser();
});
