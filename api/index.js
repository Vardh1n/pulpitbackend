const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
const path = require('path');

// Add dotenv configuration pointing to the correct .env file
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

// Validate required environment variables
const requiredEnvVars = ['MONGODB_URI'];
const missingEnvVars = requiredEnvVars.filter(varName => !process.env[varName]);

if (missingEnvVars.length > 0) {
    console.error('Missing required environment variables:', missingEnvVars);
    process.exit(1);
}

console.log('Environment check passed');

// Import database utilities
const {
    connectDB,
    createArticle,
    getAllArticles,
    getArticleById,
    getArticlesByTags,
    getArticlesByAuthors,
    getTopperArticles,
    getFeaturedArticles,
    searchArticlesByTitle,
    searchArticles,
    getArticlesByDateRange,
    updateArticle,
    deleteArticle,
    incrementViews,
    toggleFeatured,
    toggleTopper,
    getArticleStats
} = require('../databaseUtils');

const app = express();

// Initialize database connection at startup
let dbInitialized = false;

const initializeDatabase = async () => {
    if (dbInitialized) return;
    
    try {
        console.log('Initializing database connection...');
        await connectDB();
        dbInitialized = true;
        console.log('Database initialized successfully');
    } catch (error) {
        console.error('Failed to initialize database:', error);
        throw error;
    }
};

// Initialize database immediately
initializeDatabase().catch(err => {
    console.error('Database initialization failed:', err);
    process.exit(1);
});

// Simplified connection check middleware
const checkDBConnection = (req, res, next) => {
    if (mongoose.connection.readyState === 1) {
        return next();
    }
    
    // For routes that don't need database
    const skipRoutes = ['/', '/api', '/api/health', '/api/test'];
    if (skipRoutes.includes(req.path)) {
        return next();
    }
    
    return res.status(500).json({
        success: false,
        message: 'Database not connected'
    });
};

// JWT Configuration
const JWT_SECRET = process.env.JWT_SECRET || 'development-jwt-secret';
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET || 'development-refresh-secret';

const ACCESS_TOKEN_EXPIRES_IN = '30d';
const REFRESH_TOKEN_EXPIRES_IN = '90d';

// Middleware
app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false
}));

app.use(cors({
    origin: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
    credentials: true,
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'Origin']
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Request logging
app.use((req, res, next) => {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
    next();
});

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { error: 'Too many requests' }
});
app.use(limiter);

// Apply the simpler connection check
app.use(checkDBConnection);

// Error handler wrapper
const asyncHandler = (fn) => (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
};

// User Schema
const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true,
        trim: true
    },
    password: {
        type: String,
        required: true
    },
    role: {
        type: String,
        enum: ['admin', 'editor'],
        default: 'editor'
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
    refreshToken: String
});

userSchema.pre('save', async function(next) {
    if (!this.isModified('password')) return next();
    
    try {
        const salt = await bcrypt.genSalt(10);
        this.password = await bcrypt.hash(this.password, salt);
        next();
    } catch (error) {
        next(error);
    }
});

const User = mongoose.models.User || mongoose.model('User', userSchema);

// Contact Schema
const contactSubmissionSchema = new mongoose.Schema({
    name: { type: String, default: 'Anonymous' },
    email: { type: String, default: 'No contact provided' },
    message: { type: String, required: true },
    timestamp: { type: Date, default: Date.now },
    ipAddress: String,
    userAgent: String
});

const ContactSubmission = mongoose.models.ContactSubmission || mongoose.model('ContactSubmission', contactSubmissionSchema);

// Authentication middleware
const authenticate = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ message: 'Authentication required' });
        }
        
        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        
        const user = await User.findById(decoded.id);
        if (!user) {
            return res.status(401).json({ message: 'User not found' });
        }
        
        req.user = {
            id: user._id,
            username: user.username,
            role: user.role
        };
        
        next();
    } catch (error) {
        return res.status(401).json({ message: 'Invalid token' });
    }
};

// Validation middleware
const validateArticleData = (req, res, next) => {
    const { title, tags, maintext, authorname } = req.body;
    
    if (!title || !tags || !maintext || !authorname) {
        return res.status(400).json({
            success: false,
            message: 'Missing required fields'
        });
    }
    
    if (!Array.isArray(tags) || tags.length === 0) {
        return res.status(400).json({
            success: false,
            message: 'Tags must be a non-empty array'
        });
    }
    
    if (!Array.isArray(authorname) || authorname.length === 0) {
        return res.status(400).json({
            success: false,
            message: 'Author names must be a non-empty array'
        });
    }
    
    next();
};

// Rate limiters
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: { error: 'Too many login attempts' }
});

const contactLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 3,
    message: { error: 'Too many contact submissions' }
});

// Routes
app.get('/', (req, res) => {
    res.json({
        success: true,
        message: 'Pulpit Backend API',
        version: '1.0.0',
        timestamp: new Date().toISOString()
    });
});

app.get('/api', (req, res) => {
    res.json({ 
        status: 'ok', 
        message: 'API is running',
        timestamp: new Date().toISOString()
    });
});

app.get('/api/health', (req, res) => {
    res.json({
        success: true,
        message: 'Server is running',
        timestamp: new Date().toISOString(),
        env: process.env.NODE_ENV || 'development'
    });
});

app.get('/api/test', (req, res) => {
    res.json({
        success: true,
        message: 'Test endpoint working',
        timestamp: new Date().toISOString()
    });
});

// Auth routes
app.post('/api/auth/register', asyncHandler(async (req, res) => {
    const { username, password, role } = req.body;
    
    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password required' });
    }
    
    const existingUser = await User.findOne({ username });
    if (existingUser) {
        return res.status(400).json({ message: 'Username already exists' });
    }
    
    const user = new User({
        username,
        password,
        role: role || 'editor'
    });
    
    await user.save();
    
    res.status(201).json({ 
        success: true,
        message: 'User created successfully' 
    });
}));

app.post('/api/auth/login', authLimiter, asyncHandler(async (req, res) => {
    const { username, password } = req.body;
    
    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password required' });
    }
    
    const user = await User.findOne({ username });
    if (!user) {
        return res.status(401).json({ message: 'Invalid credentials' });
    }
    
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
        return res.status(401).json({ message: 'Invalid credentials' });
    }
    
    const accessToken = jwt.sign(
        { id: user._id, username: user.username, role: user.role },
        JWT_SECRET,
        { expiresIn: ACCESS_TOKEN_EXPIRES_IN }
    );
    
    const refreshToken = jwt.sign(
        { id: user._id },
        REFRESH_TOKEN_SECRET,
        { expiresIn: REFRESH_TOKEN_EXPIRES_IN }
    );
    
    user.refreshToken = refreshToken;
    await user.save();
    
    res.json({
        success: true,
        accessToken,
        refreshToken,
        user: {
            id: user._id,
            username: user.username,
            role: user.role
        }
    });
}));

app.post('/api/auth/refresh', asyncHandler(async (req, res) => {
    const { refreshToken } = req.body;
    
    if (!refreshToken) {
        return res.status(401).json({ message: 'Refresh token required' });
    }
    
    const decoded = jwt.verify(refreshToken, REFRESH_TOKEN_SECRET);
    const user = await User.findById(decoded.id);
    
    if (!user || user.refreshToken !== refreshToken) {
        return res.status(403).json({ message: 'Invalid refresh token' });
    }
    
    const accessToken = jwt.sign(
        { id: user._id, username: user.username, role: user.role },
        JWT_SECRET,
        { expiresIn: ACCESS_TOKEN_EXPIRES_IN }
    );
    
    res.json({ 
        success: true,
        accessToken 
    });
}));

// Contact form
app.post('/api/contact', contactLimiter, asyncHandler(async (req, res) => {
    const { name, email, message } = req.body;

    if (!message || !message.trim()) {
        return res.status(400).json({
            success: false,
            error: 'Message is required'
        });
    }

    const ipAddress = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    const userAgent = req.headers['user-agent'];

    const submission = new ContactSubmission({
        name: name?.trim() || 'Anonymous',
        email: email?.trim() || 'No contact provided',
        message: message.trim(),
        ipAddress,
        userAgent
    });

    await submission.save();

    res.status(200).json({
        success: true,
        message: 'Message received',
        submissionId: submission._id
    });
}));

// Admin contact submissions
app.get('/api/admin/contact-submissions', authenticate, asyncHandler(async (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Admin access required' });
    }

    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;

    const submissions = await ContactSubmission.find()
        .sort({ timestamp: -1 })
        .skip(skip)
        .limit(limit);

    const total = await ContactSubmission.countDocuments();

    res.json({
        success: true,
        submissions,
        pagination: {
            current: page,
            pages: Math.ceil(total / limit),
            total
        }
    });
}));

// Article routes
app.get('/api/articles/special/toppers', asyncHandler(async (req, res) => {
    const { limit = 5 } = req.query;
    const articles = await getTopperArticles(parseInt(limit));
    res.json({ success: true, data: articles });
}));

app.get('/api/articles/special/featured', asyncHandler(async (req, res) => {
    const { limit = 10 } = req.query;
    const articles = await getFeaturedArticles(parseInt(limit));
    res.json({ success: true, data: articles });
}));

app.get('/api/articles/search/title', asyncHandler(async (req, res) => {
    const { q, page = 1, limit = 10 } = req.query;
    
    if (!q) {
        return res.status(400).json({
            success: false,
            message: 'Search query required'
        });
    }
    
    const result = await searchArticlesByTitle(q, parseInt(page), parseInt(limit));
    res.json({ success: true, data: result });
}));

app.get('/api/articles/search/full', asyncHandler(async (req, res) => {
    const { q, page = 1, limit = 10 } = req.query;
    
    if (!q) {
        return res.status(400).json({
            success: false,
            message: 'Search query required'
        });
    }
    
    const result = await searchArticles(q, parseInt(page), parseInt(limit));
    res.json({ success: true, data: result });
}));

app.get('/api/articles/date-range', asyncHandler(async (req, res) => {
    const { startDate, endDate, page = 1, limit = 10 } = req.query;
    
    if (!startDate || !endDate) {
        return res.status(400).json({
            success: false,
            message: 'Start and end dates required'
        });
    }
    
    const result = await getArticlesByDateRange(startDate, endDate, parseInt(page), parseInt(limit));
    res.json({ success: true, data: result });
}));

app.get('/api/articles/tags/:tags', asyncHandler(async (req, res) => {
    const { page = 1, limit = 10 } = req.query;
    const tags = req.params.tags.split(',').map(tag => tag.trim());
    const result = await getArticlesByTags(tags, parseInt(page), parseInt(limit));
    res.json({ success: true, data: result });
}));

app.get('/api/articles/authors/:authors', asyncHandler(async (req, res) => {
    const { page = 1, limit = 10 } = req.query;
    const authors = req.params.authors.split(',').map(author => author.trim());
    const result = await getArticlesByAuthors(authors, parseInt(page), parseInt(limit));
    res.json({ success: true, data: result });
}));

app.get('/api/articles/:id', asyncHandler(async (req, res) => {
    const article = await getArticleById(req.params.id);
    res.json({ success: true, data: article });
}));

app.get('/api/articles', asyncHandler(async (req, res) => {
    const { page = 1, limit = 10, status = 'published' } = req.query;
    const result = await getAllArticles(parseInt(page), parseInt(limit), status);
    res.json({ success: true, data: result });
}));

app.post('/api/articles', authenticate, validateArticleData, asyncHandler(async (req, res) => {
    if (!['admin', 'editor'].includes(req.user.role)) {
        return res.status(403).json({ message: 'Not authorized' });
    }
    
    const article = await createArticle(req.body);
    res.status(201).json({
        success: true,
        message: 'Article created',
        data: article
    });
}));

app.put('/api/articles/:id', authenticate, asyncHandler(async (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Admin access required' });
    }
    
    const article = await updateArticle(req.params.id, req.body);
    res.json({
        success: true,
        message: 'Article updated',
        data: article
    });
}));

app.delete('/api/articles/:id', authenticate, asyncHandler(async (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Admin access required' });
    }
    
    const article = await deleteArticle(req.params.id);
    res.json({
        success: true,
        message: 'Article deleted',
        data: article
    });
}));

app.patch('/api/articles/:id/views', asyncHandler(async (req, res) => {
    const article = await incrementViews(req.params.id);
    res.json({
        success: true,
        message: 'Views incremented',
        data: article
    });
}));

app.patch('/api/articles/:id/featured', authenticate, asyncHandler(async (req, res) => {
    if (!['admin', 'editor'].includes(req.user.role)) {
        return res.status(403).json({ message: 'Not authorized' });
    }
    
    const article = await toggleFeatured(req.params.id);
    res.json({
        success: true,
        message: 'Featured toggled',
        data: article
    });
}));

app.patch('/api/articles/:id/topper', authenticate, asyncHandler(async (req, res) => {
    if (!['admin', 'editor'].includes(req.user.role)) {
        return res.status(403).json({ message: 'Not authorized' });
    }
    
    const article = await toggleTopper(req.params.id);
    res.json({
        success: true,
        message: 'Topper toggled',
        data: article
    });
}));

app.get('/api/analytics/stats', asyncHandler(async (req, res) => {
    const stats = await getArticleStats();
    res.json({ success: true, data: stats });
}));

// Database connection test endpoint
app.get('/api/db-test', asyncHandler(async (req, res) => {
    try {
        const dbState = mongoose.connection.readyState;
        const stateMap = {
            0: 'disconnected',
            1: 'connected',
            2: 'connecting',
            3: 'disconnecting'
        };
        
        if (dbState === 1) {
            // Test with a simple query
            const testResult = await mongoose.connection.db.admin().ping();
            res.json({
                success: true,
                message: 'Database connection is healthy',
                state: stateMap[dbState],
                ping: testResult
            });
        } else {
            res.json({
                success: false,
                message: 'Database not connected',
                state: stateMap[dbState]
            });
        }
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Database connection test failed',
            error: error.message
        });
    }
}));

// 404 handler
app.use('*', (req, res) => {
    res.status(404).json({
        success: false,
        message: 'Route not found'
    });
});

// Error handler
app.use((error, req, res, next) => {
    console.error('Error:', error.message);
    
    if (error.name === 'ValidationError') {
        return res.status(400).json({
            success: false,
            message: 'Validation Error'
        });
    }
    
    if (error.name === 'CastError') {
        return res.status(400).json({
            success: false,
            message: 'Invalid ID format'
        });
    }
    
    if (error.name === 'JsonWebTokenError') {
        return res.status(401).json({
            success: false,
            message: 'Invalid token'
        });
    }
    
    res.status(500).json({
        success: false,
        message: 'Internal server error'
    });
});

module.exports = app;