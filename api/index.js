const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

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
} = require('../databaseUtils');

const app = express();

// Middleware
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again later.'
});
app.use('/', limiter);

// Database connection middleware for serverless
const ensureDBConnection = async (req, res, next) => {
    try {
        await connectDB();
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

// Routes (remove /api prefix since we're in the api directory)

// Health check
app.get('/health', (req, res) => {
    res.json({
        success: true,
        message: 'Server is running',
        timestamp: new Date().toISOString()
    });
});

// ...existing code... (all your routes but remove /api prefix)

// Error handling middleware
app.use((error, req, res, next) => {
    console.error('Error:', error.message);
    
    // MongoDB validation errors
    if (error.name === 'ValidationError') {
        const errors = Object.values(error.errors).map(err => err.message);
        return res.status(400).json({
            success: false,
            message: 'Validation Error',
            errors
        });
    }
    
    // MongoDB cast errors (invalid ObjectId)
    if (error.name === 'CastError') {
        return res.status(400).json({
            success: false,
            message: 'Invalid ID format'
        });
    }
    
    // Duplicate key error
    if (error.code === 11000) {
        return res.status(400).json({
            success: false,
            message: 'Duplicate field value'
        });
    }
    
    // Default error
    res.status(500).json({
        success: false,
        message: error.message || 'Internal server error'
    });
});

// Export the app for Vercel
module.exports = app;