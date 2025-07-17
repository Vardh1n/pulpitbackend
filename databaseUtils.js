const mongoose = require('mongoose');

const connectDB = async () => {
    try {
        if (mongoose.connection.readyState === 1) {
            console.log('MongoDB already connected');
            return mongoose.connection;
        }
        
        if (mongoose.connection.readyState === 2) {
            console.log('MongoDB connection pending...');
        }
        
        console.log('Attempting to connect to MongoDB...');
        console.log('MongoDB URI:', process.env.MONGODB_URI ? 'URI found' : 'URI not found');
        
        const conn = await mongoose.connect(process.env.MONGODB_URI, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
            serverSelectionTimeoutMS: 10000, // Increased timeout
            socketTimeoutMS: 45000,
            maxPoolSize: 10,
            bufferMaxEntries: 0,
            connectTimeoutMS: 10000,
        });
        
        console.log(`MongoDB Connected: ${conn.connection.host}`);
        return conn;
    } catch (error) {
        console.error('Database connection error details:');
        console.error('Error name:', error.name);
        console.error('Error message:', error.message);
        console.error('Error code:', error.code);
        console.error('Full error:', error);
        throw error;
    }
};

// Article Schema
const articleSchema = new mongoose.Schema({
    title: {
        type: String,
        required: true,
        trim: true,
        maxlength: 200
    },
    tags: [{
        type: String,
        enum: ['Poem', 'Prose', 'Essay', 'Short Story', 'Review', 'Interview', 'Editorial', 'Opinion'],
        required: true
    }],
    image: {
        type: String,
        default: null
    },
    maintext: {
        type: String,
        required: true
    },
    authorname: [{
        type: String,
        required: true,
        trim: true
    }],
    date: {
        type: Date,
        default: Date.now
    },
    featured: {
        type: Boolean,
        default: false
    },
    topper: {
        type: Boolean,
        default: false
    },
    views: {
        type: Number,
        default: 0
    },
    likes: {
        type: Number,
        default: 0
    },
    status: {
        type: String,
        enum: ['draft', 'published', 'archived'],
        default: 'draft'
    }
}, {
    timestamps: true
});

// Create indexes for better query performance
articleSchema.index({ title: 'text', maintext: 'text' });
articleSchema.index({ tags: 1 });
articleSchema.index({ authorname: 1 });
articleSchema.index({ date: -1 });
articleSchema.index({ featured: 1 });
articleSchema.index({ topper: 1 });
articleSchema.index({ status: 1 });

const Article = mongoose.model('Article', articleSchema);

// CRUD Operations

// Create Article
const createArticle = async (articleData) => {
    try {
        const article = new Article(articleData);
        return await article.save();
    } catch (error) {
        throw new Error(`Error creating article: ${error.message}`);
    }
};

// Read Operations

// Get all articles with pagination
const getAllArticles = async (page = 1, limit = 10, status = 'published') => {
    try {
        const skip = (page - 1) * limit;
        const articles = await Article.find({ status })
            .sort({ date: -1 })
            .skip(skip)
            .limit(limit);

        const total = await Article.countDocuments({ status });

        return {
            articles,
            totalPages: Math.ceil(total / limit),
            currentPage: page,
            totalArticles: total
        };
    } catch (error) {
        throw new Error(`Error fetching articles: ${error.message}`);
    }
};

// Get article by ID
const getArticleById = async (id) => {
    try {
        const article = await Article.findById(id);
        if (!article) {
            throw new Error('Article not found');
        }
        return article;
    } catch (error) {
        throw new Error(`Error fetching article: ${error.message}`);
    }
};

// Get articles by tag(s)
const getArticlesByTags = async (tags, page = 1, limit = 10) => {
    try {
        const skip = (page - 1) * limit;
        const tagArray = Array.isArray(tags) ? tags : [tags];

        const articles = await Article.find({
            tags: { $in: tagArray },
            status: 'published'
        })
            .sort({ date: -1 })
            .skip(skip)
            .limit(limit);

        const total = await Article.countDocuments({
            tags: { $in: tagArray },
            status: 'published'
        });

        return {
            articles,
            totalPages: Math.ceil(total / limit),
            currentPage: page,
            totalArticles: total
        };
    } catch (error) {
        throw new Error(`Error fetching articles by tags: ${error.message}`);
    }
};

// Get articles by author(s)
const getArticlesByAuthors = async (authors, page = 1, limit = 10) => {
    try {
        const skip = (page - 1) * limit;
        const authorArray = Array.isArray(authors) ? authors : [authors];

        const articles = await Article.find({
            authorname: { $in: authorArray },
            status: 'published'
        })
            .sort({ date: -1 })
            .skip(skip)
            .limit(limit);

        const total = await Article.countDocuments({
            authorname: { $in: authorArray },
            status: 'published'
        });

        return {
            articles,
            totalPages: Math.ceil(total / limit),
            currentPage: page,
            totalArticles: total
        };
    } catch (error) {
        throw new Error(`Error fetching articles by authors: ${error.message}`);
    }
};

// Get topper articles
const getTopperArticles = async (limit = 5) => {
    try {
        return await Article.find({ topper: true, status: 'published' })
            .sort({ date: -1 })
            .limit(limit);
    } catch (error) {
        throw new Error(`Error fetching topper articles: ${error.message}`);
    }
};

// Get featured articles
const getFeaturedArticles = async (limit = 10) => {
    try {
        return await Article.find({ featured: true, status: 'published' })
            .sort({ date: -1 })
            .limit(limit);
    } catch (error) {
        throw new Error(`Error fetching featured articles: ${error.message}`);
    }
};

// Search articles by title (partial match)
const searchArticlesByTitle = async (searchTerm, page = 1, limit = 10) => {
    try {
        const skip = (page - 1) * limit;

        const articles = await Article.find({
            title: { $regex: searchTerm, $options: 'i' },
            status: 'published'
        })
            .sort({ date: -1 })
            .skip(skip)
            .limit(limit);

        const total = await Article.countDocuments({
            title: { $regex: searchTerm, $options: 'i' },
            status: 'published'
        });

        return {
            articles,
            totalPages: Math.ceil(total / limit),
            currentPage: page,
            totalArticles: total
        };
    } catch (error) {
        throw new Error(`Error searching articles: ${error.message}`);
    }
};

// Full text search
const searchArticles = async (searchTerm, page = 1, limit = 10) => {
    try {
        const skip = (page - 1) * limit;

        const articles = await Article.find({
            $text: { $search: searchTerm },
            status: 'published'
        })
            .sort({ score: { $meta: 'textScore' } })
            .skip(skip)
            .limit(limit);

        const total = await Article.countDocuments({
            $text: { $search: searchTerm },
            status: 'published'
        });

        return {
            articles,
            totalPages: Math.ceil(total / limit),
            currentPage: page,
            totalArticles: total
        };
    } catch (error) {
        throw new Error(`Error searching articles: ${error.message}`);
    }
};

// Get articles by date range
const getArticlesByDateRange = async (startDate, endDate, page = 1, limit = 10) => {
    try {
        const skip = (page - 1) * limit;

        const articles = await Article.find({
            date: { $gte: new Date(startDate), $lte: new Date(endDate) },
            status: 'published'
        })
            .sort({ date: -1 })
            .skip(skip)
            .limit(limit);

        const total = await Article.countDocuments({
            date: { $gte: new Date(startDate), $lte: new Date(endDate) },
            status: 'published'
        });

        return {
            articles,
            totalPages: Math.ceil(total / limit),
            currentPage: page,
            totalArticles: total
        };
    } catch (error) {
        throw new Error(`Error fetching articles by date range: ${error.message}`);
    }
};

// Update Article
const updateArticle = async (id, updateData) => {
    try {
        const article = await Article.findByIdAndUpdate(
            id,
            updateData,
            { new: true, runValidators: true }
        );

        if (!article) {
            throw new Error('Article not found');
        }

        return article;
    } catch (error) {
        throw new Error(`Error updating article: ${error.message}`);
    }
};

// Delete Article
const deleteArticle = async (id) => {
    try {
        const article = await Article.findByIdAndDelete(id);

        if (!article) {
            throw new Error('Article not found');
        }

        return article;
    } catch (error) {
        throw new Error(`Error deleting article: ${error.message}`);
    }
};

// Utility Functions

// Increment article views
const incrementViews = async (id) => {
    try {
        return await Article.findByIdAndUpdate(
            id,
            { $inc: { views: 1 } },
            { new: true }
        );
    } catch (error) {
        throw new Error(`Error incrementing views: ${error.message}`);
    }
};

// Toggle featured status
const toggleFeatured = async (id) => {
    try {
        const article = await Article.findById(id);
        if (!article) {
            throw new Error('Article not found');
        }

        article.featured = !article.featured;
        return await article.save();
    } catch (error) {
        throw new Error(`Error toggling featured status: ${error.message}`);
    }
};

// Toggle topper status
const toggleTopper = async (id) => {
    try {
        const article = await Article.findById(id);
        if (!article) {
            throw new Error('Article not found');
        }

        article.topper = !article.topper;
        return await article.save();
    } catch (error) {
        throw new Error(`Error toggling topper status: ${error.message}`);
    }
};

// Get article statistics
const getArticleStats = async () => {
    try {
        const totalArticles = await Article.countDocuments();
        const publishedArticles = await Article.countDocuments({ status: 'published' });
        const draftArticles = await Article.countDocuments({ status: 'draft' });
        const featuredArticles = await Article.countDocuments({ featured: true });
        const topperArticles = await Article.countDocuments({ topper: true });

        const tagStats = await Article.aggregate([
            { $unwind: '$tags' },
            { $group: { _id: '$tags', count: { $sum: 1 } } },
            { $sort: { count: -1 } }
        ]);

        const authorStats = await Article.aggregate([
            { $unwind: '$authorname' },
            { $group: { _id: '$authorname', count: { $sum: 1 } } },
            { $sort: { count: -1 } }
        ]);

        return {
            totalArticles,
            publishedArticles,
            draftArticles,
            featuredArticles,
            topperArticles,
            tagStats,
            authorStats
        };
    } catch (error) {
        throw new Error(`Error getting article stats: ${error.message}`);
    }
};

module.exports = {
    connectDB,
    Article,
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
};