const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');

// Add dotenv configuration at the top
require('dotenv').config();

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
} = require('./databaseUtils');

const app = express();
const PORT = process.env.PORT || 5000;

// JWT Configuration
const JWT_SECRET = process.env.JWT_SECRET || 'development-jwt-secret';
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET || 'development-refresh-secret';

if (process.env.NODE_ENV === 'production' && (!JWT_SECRET || !REFRESH_TOKEN_SECRET)) {
    console.error('Warning: JWT_SECRET and/or REFRESH_TOKEN_SECRET not set in production environment');
}

const JWT_EXPIRES_IN = '1h';
const ACCESS_TOKEN_EXPIRES_IN = '30d';
const REFRESH_TOKEN_EXPIRES_IN = '90d';

// Middleware with relaxed settings for Vercel deployment
app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false
}));

// Allowed origins for CORS
const allowedOrigins = ['*'];

// API access middleware
const apiAccessMiddleware = (req, res, next) => {
    const isAPIRequest = req.path.startsWith('/api/');
    const isBrowserRequest = req.headers['sec-fetch-mode'] === 'navigate';
    
    if (isAPIRequest && isBrowserRequest) {
        return res.status(403).json({
            error: 'Direct browser access to API endpoints is not allowed',
            message: 'Please access the API through the frontend application'
        });
    }
    
    next();
};

// Apply API access middleware before CORS
//app.use(apiAccessMiddleware);

app.use(cors({
    origin: true, // Allow all origins
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    credentials: true,
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'Origin']
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Add request logging middleware
app.use((req, res, next) => {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.path} - Origin: ${req.headers.origin} - Sec-Fetch-Mode: ${req.headers['sec-fetch-mode']}`);
    next();
});

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again later.'
});
app.use('/', limiter);

// Add this before your routes
app.use((req, res, next) => {
    // Set a timeout for serverless functions (Vercel has 10s limit for hobby plan)
    const timeout = setTimeout(() => {
        if (!res.headersSent) {
            res.status(504).json({
                success: false,
                message: 'Request timeout'
            });
        }
    }, 9000); // 9 seconds to be safe
    
    res.on('finish', () => clearTimeout(timeout));
    next();
});
let cachedDb = null;

// Database connection middleware for serverless
const ensureDBConnection = async (req, res, next) => {
    try {
        // Check if already connected
        if (mongoose.connection.readyState === 1) {
            return next();
        }
        
        // Connect to database
        await connectDB();
        console.log('Successfully connected to MongoDB');
        next();
    } catch (error) {
        console.error('Database connection error:', error);
        res.status(500).json({
            success: false,
            message: 'Database connection failed'
        });
    }
};

// Apply DB connection middleware to all routes
app.use('/', ensureDBConnection);

// Error handling middleware
const asyncHandler = (fn) => (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
};

// User Schema (add this to your databaseUtils or create a separate models file)
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
    refreshToken: {
        type: String
    }
});

// Hash password before saving
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

const User = mongoose.model('User', userSchema);

// Contact form schema
const contactSubmissionSchema = new mongoose.Schema({
    name: {
        type: String,
        default: 'Anonymous'
    },
    email: {
        type: String,
        default: 'No contact provided'
    },
    message: {
        type: String,
        required: true
    },
    timestamp: {
        type: Date,
        default: Date.now
    },
    ipAddress: {
        type: String
    },
    userAgent: {
        type: String
    }
});

const ContactSubmission = mongoose.model('ContactSubmission', contactSubmissionSchema);

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
            message: 'Missing required fields: title, tags, maintext, authorname'
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

// Rate limiter for auth routes
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 attempts
    message: 'Too many login attempts, please try again later'
});

// Rate limiter for contact form
const contactLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 3, // 3 submissions per 15 minutes per IP
    message: {
        error: 'Too many contact form submissions. Please try again later.',
        retryAfter: '15 minutes'
    }
});

// Routes

// Root route - API documentation
app.get('/', (req, res) => {
    res.json({
        success: true,
        message: 'Pulpit Backend API',
        version: '1.0.0',
        endpoints: {
            health: '/api/health',
            articles: '/api/articles',
            featured: '/api/articles/special/featured',
            toppers: '/api/articles/special/toppers',
            search: '/api/articles/search/title?q=query',
            analytics: '/api/analytics/stats',
            auth: '/api/auth/login',
            contact: '/api/contact'
        },
        timestamp: new Date().toISOString()
    });
});

// API root route
app.get('/api', (req, res) => {
    res.status(200).json({ 
        status: 'ok', 
        message: 'Pulpit Backend API is running'
    });
});

// Health check
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
    
    // Check if user already exists
    const existingUser = await User.findOne({ username });
    if (existingUser) {
        return res.status(400).json({ message: 'Username already exists' });
    }
    
    // Create new user
    const user = new User({
        username,
        password,
        role: role || 'editor'
    });
    
    await user.save();
    
    res.status(201).json({ message: 'User created successfully' });
}));

app.post('/api/auth/login', authLimiter, asyncHandler(async (req, res) => {
    const { username, password } = req.body;
    
    // Find user
    const user = await User.findOne({ username });
    if (!user) {
        return res.status(401).json({ message: 'Invalid credentials' });
    }
    
    // Verify password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
        return res.status(401).json({ message: 'Invalid credentials' });
    }
    
    // Generate access token
    const accessToken = jwt.sign(
        { id: user._id, username: user.username, role: user.role },
        JWT_SECRET,
        { expiresIn: ACCESS_TOKEN_EXPIRES_IN }
    );
    
    // Generate refresh token
    const refreshToken = jwt.sign(
        { id: user._id },
        REFRESH_TOKEN_SECRET,
        { expiresIn: REFRESH_TOKEN_EXPIRES_IN }
    );
    
    // Store refresh token
    user.refreshToken = refreshToken;
    await user.save();
    
    res.json({
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
    
    // Verify refresh token
    const decoded = jwt.verify(refreshToken, REFRESH_TOKEN_SECRET);
    
    // Find user with this refresh token
    const user = await User.findById(decoded.id);
    
    if (!user || user.refreshToken !== refreshToken) {
        return res.status(403).json({ message: 'Invalid refresh token' });
    }
    
    // Generate new access token
    const accessToken = jwt.sign(
        { id: user._id, username: user.username, role: user.role },
        JWT_SECRET,
        { expiresIn: ACCESS_TOKEN_EXPIRES_IN }
    );
    
    res.json({ accessToken });
}));

// Contact form endpoint
app.post('/api/contact', contactLimiter, asyncHandler(async (req, res) => {
    const { name, email, message } = req.body;

    // Validate required fields
    if (!message || !message.trim()) {
        return res.status(400).json({
            error: 'Message is required'
        });
    }

    // Get client IP and User Agent for security logging
    const ipAddress = req.ip || req.connection.remoteAddress || req.headers['x-forwarded-for'];
    const userAgent = req.headers['user-agent'];

    // Create and save submission
    const submission = new ContactSubmission({
        name: name?.trim() || 'Anonymous',
        email: email?.trim() || 'No contact provided',
        message: message.trim(),
        ipAddress,
        userAgent,
        timestamp: new Date()
    });

    await submission.save();

    console.log(`Contact form submission saved: ${submission._id} from ${submission.name}`);

    res.status(200).json({
        success: true,
        message: 'Your message has been received securely. We will review it and respond if necessary.',
        submissionId: submission._id
    });
}));

// Admin endpoint to view contact submissions
app.get('/api/admin/contact-submissions', authenticate, asyncHandler(async (req, res) => {
    // Check if user has admin permission
    if (req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Admin access required' });
    }

    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;

    const submissions = await ContactSubmission.find()
        .sort({ timestamp: -1 })
        .skip(skip)
        .limit(limit)
        .select('-__v');

    const total = await ContactSubmission.countDocuments();

    res.json({
        submissions,
        pagination: {
            current: page,
            pages: Math.ceil(total / limit),
            total
        }
    });
}));

// Move specific routes BEFORE the general /api/articles route
app.get('/api/articles/special/toppers', asyncHandler(async (req, res) => {
    const { limit = 5 } = req.query;
    const articles = await getTopperArticles(parseInt(limit));
    res.json({
        success: true,
        data: articles
    });
}));

app.get('/api/articles/special/featured', asyncHandler(async (req, res) => {
    const { limit = 10 } = req.query;
    const articles = await getFeaturedArticles(parseInt(limit));
    res.json({
        success: true,
        data: articles
    });
}));

app.get('/api/articles/search/title', asyncHandler(async (req, res) => {
    const { q, page = 1, limit = 10 } = req.query;
    
    if (!q) {
        return res.status(400).json({
            success: false,
            message: 'Search query is required'
        });
    }
    
    const result = await searchArticlesByTitle(q, parseInt(page), parseInt(limit));
    res.json({
        success: true,
        data: result
    });
}));

app.get('/api/articles/search/full', asyncHandler(async (req, res) => {
    const { q, page = 1, limit = 10 } = req.query;
    
    if (!q) {
        return res.status(400).json({
            success: false,
            message: 'Search query is required'
        });
    }
    
    const result = await searchArticles(q, parseInt(page), parseInt(limit));
    res.json({
        success: true,
        data: result
    });
}));

app.get('/api/articles/date-range', asyncHandler(async (req, res) => {
    const { startDate, endDate, page = 1, limit = 10 } = req.query;
    
    if (!startDate || !endDate) {
        return res.status(400).json({
            success: false,
            message: 'Both startDate and endDate are required'
        });
    }
    
    const result = await getArticlesByDateRange(startDate, endDate, parseInt(page), parseInt(limit));
    res.json({
        success: true,
        data: result
    });
}));

app.get('/api/articles/tags/:tags', asyncHandler(async (req, res) => {
    const { page = 1, limit = 10 } = req.query;
    const tags = req.params.tags.split(',').map(tag => tag.trim());
    const result = await getArticlesByTags(tags, parseInt(page), parseInt(limit));
    res.json({
        success: true,
        data: result
    });
}));

app.get('/api/articles/authors/:authors', asyncHandler(async (req, res) => {
    const { page = 1, limit = 10 } = req.query;
    const authors = req.params.authors.split(',').map(author => author.trim());
    const result = await getArticlesByAuthors(authors, parseInt(page), parseInt(limit));
    res.json({
        success: true,
        data: result
    });
}));

app.get('/api/articles/:id', asyncHandler(async (req, res) => {
    const article = await getArticleById(req.params.id);
    res.json({
        success: true,
        data: article
    });
}));

app.get('/api/articles', asyncHandler(async (req, res) => {
    const { page = 1, limit = 10, status = 'published' } = req.query;
    const result = await getAllArticles(parseInt(page), parseInt(limit), status);
    res.json({
        success: true,
        data: result
    });
}));

app.post('/api/articles', authenticate, validateArticleData, asyncHandler(async (req, res) => {
    // Check if user has permission (admin or editor)
    if (!['admin', 'editor'].includes(req.user.role)) {
        return res.status(403).json({ message: 'Not authorized' });
    }
    
    const article = await createArticle(req.body);
    res.status(201).json({
        success: true,
        message: 'Article created successfully',
        data: article
    });
}));

app.put('/api/articles/:id', authenticate, asyncHandler(async (req, res) => {
    // Check if user has admin permission for updates
    if (req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Admin access required for updating articles' });
    }
    
    const article = await updateArticle(req.params.id, req.body);
    res.json({
        success: true,
        message: 'Article updated successfully',
        data: article
    });
}));

app.delete('/api/articles/:id', authenticate, asyncHandler(async (req, res) => {
    // Check if user has admin permission for deletion
    if (req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Admin access required for deleting articles' });
    }
    
    const article = await deleteArticle(req.params.id);
    res.json({
        success: true,
        message: 'Article deleted successfully',
        data: article
    });
}));

app.patch('/api/articles/:id/views', asyncHandler(async (req, res) => {
    const article = await incrementViews(req.params.id);
    res.json({
        success: true,
        message: 'Views incremented successfully',
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
        message: 'Featured status toggled successfully',
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
        message: 'Topper status toggled successfully',
        data: article
    });
}));

app.get('/api/analytics/stats', asyncHandler(async (req, res) => {
    const stats = await getArticleStats();
    res.json({
        success: true,
        data: stats
    });
}));

// 404 handler
app.use('*', (req, res) => {
    res.status(404).json({
        success: false,
        message: 'Route not found'
    });
});

// Error handling middleware
app.use((error, req, res, next) => {
    console.error('Error:', error.message);
    
    if (error.name === 'ValidationError') {
        const errors = Object.values(error.errors).map(err => err.message);
        return res.status(400).json({
            success: false,
            message: 'Validation Error',
            errors
        });
    }
    
    if (error.name === 'CastError') {
        return res.status(400).json({
            success: false,
            message: 'Invalid ID format'
        });
    }
    
    if (error.code === 11000) {
        return res.status(400).json({
            success: false,
            message: 'Duplicate field value'
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
        message: error.message || 'Internal server error'
    });
});

// Only start server if not in production (for local development)
if (process.env.NODE_ENV !== 'production') {
    app.listen(PORT, () => {
        console.log(`Server running on port ${PORT}`);
        console.log(`Health check: http://localhost:${PORT}/api/health`);
    });
}

// Export the app for Vercel
module.exports = app;