// server.js
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const serverless = require('serverless-http');
const http = require('http');
require('dotenv').config();

// Database connection
const connectDB = require('./config/database');
connectDB();

// Logger middleware
const logger = require('./middleware/logger');

const app = express();

// Trust proxy (for rate-limiting behind API Gateway / Vercel)
app.set('trust proxy', 1);

// Security middleware
app.use(helmet());

// Rate limiter
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: process.env.NODE_ENV === 'development' ? 1000 : 100,
  message: 'Too many requests from this IP, please try again later.'
});
app.use(limiter);

// CORS configuration
const allowedOrigins = [
  'http://localhost:5173',
  'http://localhost:5174',
  'https://main.daqm1aijotilg.amplifyapp.com',
  process.env.FRONTEND_URL
].filter(Boolean);

const corsOptions = {
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    if (process.env.NODE_ENV === 'development' && origin.includes('localhost')) return callback(null, true);
    if (allowedOrigins.includes(origin)) return callback(null, true);
    console.warn(`🚫 CORS blocked for origin: ${origin}`);
    return callback(null, true); // allow but log
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept'],
  exposedHeaders: ['Authorization', 'Content-Length', 'X-Request-Id'],
};
app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

// Body parser
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Debugging incoming requests
app.use((req, res, next) => {
  console.log('👉 Request Origin:', req.headers.origin || 'No origin');
  next();
});

// Routes
app.use('/api/auth', require('./routes/auth'));
app.use('/api/admin', require('./routes/admin'));
app.use('/api/settings', require('./routes/settings'));
app.use('/api/college', require('./routes/college'));
app.use('/api/tests', require('./routes/tests'));
app.use('/api/reports', require('./routes/reports'));
app.use('/api/notifications', require('./routes/notifications'));
app.use('/api/analytics', require('./routes/analytics'));
app.use('/api/subjects', require('./routes/subjects'));
app.use('/api/faculty', require('./routes/faculty'));
app.use('/api/coding', require('./routes/coding'));
app.use('/api/profile', require('./routes/profile'));
app.use('/api/coding-questions', require('./routes/codingQuestions'));

// Root route
app.get('/', (req, res) => {
  res.send('🚀 Server is running!');
});

// Serve uploaded files
const path = require('path');
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Health check
app.get('/api/health', (req, res) => {
  res.json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// Error handler
app.use((err, req, res, next) => {
  logger.errorLog(err, { context: 'Unhandled error' });
  res.status(err.statusCode || 500).json({
    error: process.env.NODE_ENV === 'development' ? err.message : 'Internal server error'
  });
});

// Create HTTP server (used when running locally)
const server = http.createServer(app);

// NOTE: Socket.IO removed — using AWS WebSocket API or other mechanism is recommended for production.
// Periodically calculate active student count and publish via a pluggable publisher.
const User = require('./models/User');
// pluggable publisher; if you later add a publish utility (e.g., to API Gateway Management API), set this function.
const publishActivityUpdate = global.publishActivityUpdate || (async (payload) => {
  // Default: just log the activity update when no real-time system is configured
  console.log('activity:update', payload);
});

const emitActiveCounts = async () => {
  try {
    const fifteenMinutesAgo = new Date(Date.now() - 15 * 60 * 1000);
    const activeStudents = await User.countDocuments({ role: 'student', lastLogin: { $gte: fifteenMinutesAgo } });
    await publishActivityUpdate({ activeStudents });
  } catch (err) {
    logger.errorLog(err, { context: 'Failed to compute active counts' });
  }
};
setInterval(emitActiveCounts, 15 * 1000);
emitActiveCounts();

// Start server locally if not Lambda
const PORT = process.env.PORT || 5000;
if (require.main === module) {
  server.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
  });
}

// Export for AWS Lambda
module.exports.handler = serverless(app);
