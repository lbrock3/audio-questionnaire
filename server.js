// Required modules
const express = require('express');
const mongoose = require('mongoose');
const multer = require('multer');
const cors = require('cors');
const path = require('path');
require('dotenv').config();

// Initialize app
const app = express();
const port = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Configure file storage (using memory storage)
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

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/audio-questionnaire')
.then(() => {
    console.log('Connected to MongoDB');
})
.catch(err => console.error('MongoDB connection error:', err));

// Create models with audio data embedded
const responseSchema = new mongoose.Schema({
    submittedAt: { type: Date, default: Date.now },
    ipAddress: String,
    userAgent: String,
    responses: [{
        questionIndex: Number,
        questionText: String,
        audioData: Buffer,
        audioContentType: String,
        audioFilename: String
    }]
});

const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    isAdmin: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now }
});

const Response = mongoose.model('Response', responseSchema);
const User = mongoose.model('User', userSchema);

// Authentication middleware
const authenticateUser = (req, res, next) => {
    const username = req.headers['username'];
    const password = req.headers['password'];

    if (!username || !password) {
        return res.status(401).json({ message: 'Authentication required' });
    }

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

// Submit questionnaire responses
app.post('/api/submit-responses', upload.array('audio_responses'), async (req, res) => {
    try {
        console.log('Submission received. Processing...');

        // Process form data
        const files = req.files;
        const questions = req.body;

        console.log(`Received ${files.length} files and ${Object.keys(questions).length} questions`);

        // Create response object
        const response = new Response({
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            responses: []
        });

        // Process files
        for (const file of files) {
            const questionIndexMatch = file.originalname.match(/question_(\d+)/);
            if (questionIndexMatch) {
                const questionIndex = parseInt(questionIndexMatch[1]) - 1;

                // Create a unique filename
                const filename = `${Date.now()}-${Math.round(Math.random() * 1E9)}-${file.originalname}`;

                // Store file directly in MongoDB
                response.responses.push({
                    questionIndex,
                    questionText: questions[`question_${questionIndex+1}`],
                    audioData: file.buffer,
                    audioContentType: file.mimetype,
                    audioFilename: filename
                });

                console.log(`Processed file for question ${questionIndex+1}`);
            }
        }

        // Save response to database
        await response.save();
        console.log('Response saved successfully');

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

// Authentication routes
app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        // Find user with direct password comparison
        const user = await User.findOne({ username });
        if (!user) return res.status(400).json({ message: 'Invalid username or password' });

        if (user.password !== password) {
            return res.status(400).json({ message: 'Invalid username or password' });
        }

        // Return user info directly
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

        // Get responses without audio data for faster loading
        const responses = await Response.find({}, { 'responses.audioData': 0 })
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
        // Get response without audio data
        const response = await Response.findById(req.params.id, { 'responses.audioData': 0 });
        if (!response) return res.status(404).json({ message: 'Response not found' });

        res.status(200).json({ response });
    } catch (error) {
        console.error('Error fetching response:', error);
        res.status(500).json({ message: 'An error occurred while fetching the response' });
    }
});

// Stream audio file directly from MongoDB
app.get('/api/admin/audio/:responseId/:index', async (req, res) => {
    try {
        const responseId = req.params.responseId;
        const index = parseInt(req.params.index);

        // Find the response and select only the specified audio data
        const response = await Response.findById(responseId);

        if (!response || !response.responses[index]) {
            return res.status(404).json({ message: 'Audio file not found' });
        }

        const audioResponse = response.responses[index];

        // Set appropriate headers
        res.set('Content-Type', audioResponse.audioContentType);

        // Send the audio data
        res.send(audioResponse.audioData);

    } catch (error) {
        console.error('Error serving audio file:', error);
        res.status(500).json({ message: 'Error serving audio file' });
    }
});

// Download audio file
app.get('/api/admin/download/:responseId/:index', async (req, res) => {
    try {
        const responseId = req.params.responseId;
        const index = parseInt(req.params.index);

        // Find the response and select only the specified audio data
        const response = await Response.findById(responseId);

        if (!response || !response.responses[index]) {
            return res.status(404).json({ message: 'Audio file not found' });
        }

        const audioResponse = response.responses[index];

        // Set appropriate headers for download
        res.set('Content-Type', audioResponse.audioContentType);
        res.set('Content-Disposition', `attachment; filename="${audioResponse.audioFilename}"`);

        // Send the audio data
        res.send(audioResponse.audioData);

    } catch (error) {
        console.error('Error downloading file:', error);
        res.status(500).json({ message: 'Error downloading file' });
    }
});

// Delete response
app.delete('/api/admin/responses/:id', authenticateUser, async (req, res) => {
    if (!req.user.isAdmin) return res.status(403).json({ message: 'Admin privileges required' });

    try {
        // Simply delete the document from MongoDB
        const result = await Response.findByIdAndDelete(req.params.id);

        if (!result) {
            return res.status(404).json({ message: 'Response not found' });
        }

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
    // Create admin user once MongoDB is connected
    mongoose.connection.once('connected', () => {
        createAdminUser();
    });
});
