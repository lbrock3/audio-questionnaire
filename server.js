// Required modules
const express = require('express');
const mongoose = require('mongoose');
const multer = require('multer');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const { GridFSBucket } = require('mongodb');
const stream = require('stream');
require('dotenv').config();

// Initialize app
const app = express();
const port = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// GridFS setup - initialize as null
let gridFSBucket = null;
let isDbConnected = false;

// Configure file storage (using memory storage for Render)
const storage = multer.memoryStorage();
const upload = multer({
    storage: storage,
    fileFilter: (req, file, cb) => {
        if (file.mimetype.startsWith('audio/')) {
            cb(null, true);
        } else {
            cb(new Error('Only audio files are allowed'));
        }
    },
    limits: {
        fileSize: 10 * 1024 * 1024 // 10MB limit
    }
});

// GridFS helper functions
const uploadToGridFS = (buffer, filename, contentType) => {
    return new Promise((resolve, reject) => {
        // Check if gridFSBucket is initialized
        if (!gridFSBucket) {
            return reject(new Error('Database connection not ready. Please try again.'));
        }

        const bufferStream = new stream.PassThrough();
        bufferStream.end(buffer);

        const uploadStream = gridFSBucket.openUploadStream(filename, {
            contentType: contentType
        });

        bufferStream.pipe(uploadStream)
        .on('error', (error) => reject(error))
        .on('finish', () => resolve(uploadStream.id));
    });
};

const deleteFromGridFS = async (filename) => {
    try {
        // Check if gridFSBucket is initialized
        if (!gridFSBucket) {
            throw new Error('Database connection not ready');
        }

        const files = await mongoose.connection.db
        .collection('audioUploads.files')
        .find({ filename: filename })
        .toArray();

        if (files.length > 0) {
            await gridFSBucket.delete(files[0]._id);
            return true;
        }
        return false;
    } catch (error) {
        console.error('Error deleting file from GridFS:', error);
        return false;
    }
};

// Connection ready middleware - ensures DB is connected before handling requests
const ensureDbConnected = (req, res, next) => {
    if (isDbConnected) {
        return next();
    }

    // If not connected, wait for connection with a timeout
    let retryCount = 0;
    const maxRetries = 20;
    const retryInterval = 500; // 0.5 seconds

    const checkConnection = () => {
        if (isDbConnected) {
            next();
            return;
        }

        retryCount++;
        if (retryCount >= maxRetries) {
            return res.status(503).json({
                success: false,
                message: 'Database connection not available. Please try again later.'
            });
        }

        setTimeout(checkConnection, retryInterval);
    };

    checkConnection();
};

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/audio-questionnaire')
.then(() => {
    console.log('Connected to MongoDB');
    // Initialize GridFS
    gridFSBucket = new GridFSBucket(mongoose.connection.db, {
        bucketName: 'audioUploads'
    });
    isDbConnected = true;
    console.log('GridFS bucket initialized');
})
.catch(err => console.error('MongoDB connection error:', err));

// Handle MongoDB disconnection
mongoose.connection.on('disconnected', () => {
    console.log('Disconnected from MongoDB');
    isDbConnected = false;
    gridFSBucket = null;
});

// Handle MongoDB reconnection
mongoose.connection.on('reconnected', () => {
    console.log('Reconnected to MongoDB');
    // Re-initialize GridFS
    gridFSBucket = new GridFSBucket(mongoose.connection.db, {
        bucketName: 'audioUploads'
    });
    isDbConnected = true;
    console.log('GridFS bucket re-initialized');
});

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

const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true }, // Plain text password - suitable for non-sensitive data
    isAdmin: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now }
});

const Response = mongoose.model('Response', responseSchema);
const User = mongoose.model('User', userSchema);

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

// Serve index page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Submit questionnaire responses - use the ensureDbConnected middleware
app.post('/api/submit-responses', ensureDbConnected, upload.array('audio_responses'), async (req, res) => {
    try {
        // Check if gridFSBucket is available
        if (!gridFSBucket) {
            throw new Error('Database connection not ready. Please try again.');
        }

        // Process form data
        const files = req.files;
        const questions = req.body;

        // Create response object
        const response = new Response({
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            responses: []
        });

        // Process files and upload to GridFS
        for (const file of files) {
            const questionIndexMatch = file.originalname.match(/question_(\d+)/);
            if (questionIndexMatch) {
                const questionIndex = parseInt(questionIndexMatch[1]) - 1;

                // Create a unique filename
                const filename = `${Date.now()}-${Math.round(Math.random() * 1E9)}-${file.originalname}`;

                // Upload to GridFS
                await uploadToGridFS(file.buffer, filename, file.mimetype);

                // Save file info to response
                response.responses.push({
                    questionIndex,
                    questionText: questions[`question_${questionIndex+1}`],
                    audioFilename: filename
                });
            }
        }

        // Save response to database
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
            message: 'An error occurred while processing your submission: ' + error.message
        });
    }
});

// Authentication routes - simplified for non-sensitive data
app.post('/api/auth/login', ensureDbConnected, async (req, res) => {
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
app.get('/api/admin/responses', ensureDbConnected, authenticateUser, async (req, res) => {
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
app.get('/api/admin/responses/:id', ensureDbConnected, authenticateUser, async (req, res) => {
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

// Stream audio file from GridFS
app.get('/api/admin/audio/:filename', ensureDbConnected, (req, res) => {
    const filename = req.params.filename;

    try {
        // Check if gridFSBucket is available
        if (!gridFSBucket) {
            throw new Error('Database connection not ready');
        }

        // Create download stream from GridFS
        const downloadStream = gridFSBucket.openDownloadStreamByName(filename);

        // Set content type
        res.set('Content-Type', 'audio/webm');

        // Handle errors
        downloadStream.on('error', (err) => {
            console.error('Error streaming file:', err);
            if (!res.headersSent) {
                res.status(404).json({ message: 'Audio file not found' });
            }
        });

        // Pipe file to response
        downloadStream.pipe(res);
    } catch (error) {
        console.error('Error accessing audio file:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Download audio file from GridFS
app.get('/api/admin/download/:filename', ensureDbConnected, (req, res) => {
    const filename = req.params.filename;

    try {
        // Check if gridFSBucket is available
        if (!gridFSBucket) {
            throw new Error('Database connection not ready');
        }

        // Create download stream from GridFS
        const downloadStream = gridFSBucket.openDownloadStreamByName(filename);

        // Set headers for download
        res.set('Content-Type', 'audio/webm');
        res.set('Content-Disposition', `attachment; filename="${filename}"`);

        // Handle errors
        downloadStream.on('error', (err) => {
            console.error('Error downloading file:', err);
            if (!res.headersSent) {
                res.status(404).json({ message: 'Audio file not found' });
            }
        });

        // Pipe file to response
        downloadStream.pipe(res);
    } catch (error) {
        console.error('Error downloading file:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Delete response
app.delete('/api/admin/responses/:id', ensureDbConnected, authenticateUser, async (req, res) => {
    if (!req.user.isAdmin) return res.status(403).json({ message: 'Admin privileges required' });

    try {
        const response = await Response.findById(req.params.id);
        if (!response) return res.status(404).json({ message: 'Response not found' });

        // Delete associated audio files from GridFS
        for (const item of response.responses) {
            try {
                await deleteFromGridFS(item.audioFilename);
            } catch (err) {
                console.error(`Error deleting file ${item.audioFilename}:`, err);
            }
        }

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
app.listen(port, '0.0.0.0', () => {
    console.log(`Server running on port ${port}, accessible at http://localhost:${port}`);
    // Create admin user once DB is connected
    mongoose.connection.once('connected', () => {
        createAdminUser();
    });
});
