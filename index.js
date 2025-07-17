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
} = require('./databaseUtils');

const app = express();
const PORT = process.env.PORT || 5000;

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
app.use('/api/', limiter);

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

// Apply DB connection middleware to all API routes
app.use('/api', ensureDBConnection);

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

// Routes

// Health check
app.get('/api/health', (req, res) => {
    res.json({
        success: true,
        message: 'Server is running',
        timestamp: new Date().toISOString()
    });
});

// CREATE - Create new article
app.post('/api/articles', validateArticleData, asyncHandler(async (req, res) => {
    const article = await createArticle(req.body);
    res.status(201).json({
        success: true,
        message: 'Article created successfully',
        data: article
    });
}));

// READ - Get all articles with pagination
app.get('/api/articles', asyncHandler(async (req, res) => {
    const { page = 1, limit = 10, status = 'published' } = req.query;
    const result = await getAllArticles(parseInt(page), parseInt(limit), status);
    res.json({
        success: true,
        data: result
    });
}));

// READ - Get article by ID
app.get('/api/articles/:id', asyncHandler(async (req, res) => {
    const article = await getArticleById(req.params.id);
    res.json({
        success: true,
        data: article
    });
}));

// READ - Get articles by tags
app.get('/api/articles/tags/:tags', asyncHandler(async (req, res) => {
    const { page = 1, limit = 10 } = req.query;
    const tags = req.params.tags.split(',').map(tag => tag.trim());
    const result = await getArticlesByTags(tags, parseInt(page), parseInt(limit));
    res.json({
        success: true,
        data: result
    });
}));

// READ - Get articles by authors
app.get('/api/articles/authors/:authors', asyncHandler(async (req, res) => {
    const { page = 1, limit = 10 } = req.query;
    const authors = req.params.authors.split(',').map(author => author.trim());
    const result = await getArticlesByAuthors(authors, parseInt(page), parseInt(limit));
    res.json({
        success: true,
        data: result
    });
}));

// READ - Get topper articles
app.get('/api/articles/special/toppers', asyncHandler(async (req, res) => {
    const { limit = 5 } = req.query;
    const articles = await getTopperArticles(parseInt(limit));
    res.json({
        success: true,
        data: articles
    });
}));

// READ - Get featured articles
app.get('/api/articles/special/featured', asyncHandler(async (req, res) => {
    const { limit = 10 } = req.query;
    const articles = await getFeaturedArticles(parseInt(limit));
    res.json({
        success: true,
        data: articles
    });
}));

// READ - Search articles by title
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

// READ - Full text search
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

// READ - Get articles by date range
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

// UPDATE - Update article
app.put('/api/articles/:id', asyncHandler(async (req, res) => {
    const article = await updateArticle(req.params.id, req.body);
    res.json({
        success: true,
        message: 'Article updated successfully',
        data: article
    });
}));

// DELETE - Delete article
app.delete('/api/articles/:id', asyncHandler(async (req, res) => {
    const article = await deleteArticle(req.params.id);
    res.json({
        success: true,
        message: 'Article deleted successfully',
        data: article
    });
}));

// UTILITY - Increment views
app.patch('/api/articles/:id/views', asyncHandler(async (req, res) => {
    const article = await incrementViews(req.params.id);
    res.json({
        success: true,
        message: 'Views incremented successfully',
        data: article
    });
}));

// UTILITY - Toggle featured status
app.patch('/api/articles/:id/featured', asyncHandler(async (req, res) => {
    const article = await toggleFeatured(req.params.id);
    res.json({
        success: true,
        message: 'Featured status toggled successfully',
        data: article
    });
}));

// UTILITY - Toggle topper status
app.patch('/api/articles/:id/topper', asyncHandler(async (req, res) => {
    const article = await toggleTopper(req.params.id);
    res.json({
        success: true,
        message: 'Topper status toggled successfully',
        data: article
    });
}));

// ANALYTICS - Get article statistics
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

// For Vercel deployment, don't start the server if we're in production
if (process.env.NODE_ENV !== 'production') {
    app.listen(PORT, () => {
        console.log(`Server running on port ${PORT}`);
        console.log(`Health check: http://localhost:${PORT}/api/health`);
    });
}

// Export the app for Vercel
module.exports = app;