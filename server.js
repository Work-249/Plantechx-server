const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const serverless = require('serverless-http');
const http = require('http');
const path = require('path');
const mongoose = require('mongoose');
require('dotenv').config();

// Bootstrap log to make startup visible in container logs
console.log('➡️  Starting server bootstrap... NODE_ENV=', process.env.NODE_ENV);
console.log('📁 Working directory:', process.cwd());
console.log('🔎 NODE_PATH:', process.env.NODE_PATH || '(not set)');
console.log('🔐 ALLOWED_ORIGINS:', process.env.ALLOWED_ORIGINS || '(not set)');
console.log('🔐 ALLOW_CREDENTIALS:', process.env.ALLOW_CREDENTIALS || '(not set)');

// Initialize logger FIRST before anything that uses it
const logger = require('./middleware/logger');

// Database connection
const connectDB = require('./config/database');

// Get configuration
const PORT = parseInt(process.env.PORT, 10) || 8080;
const HOST = '0.0.0.0'; // ensure binding to external interface

// Create Express app
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

// CORS configuration — allow explicit origins when provided
// WARNING: When using a wildcard origin, cookies and credentials cannot be used.
// Use ALLOWED_ORIGINS env var (comma-separated) in production and set ALLOW_CREDENTIALS=true only if needed.
const allowedOriginsEnv = process.env.ALLOWED_ORIGINS;
const allowedOrigins = allowedOriginsEnv ? allowedOriginsEnv.split(',').map(s => s.trim()) : null;
const allowCredentials = process.env.ALLOW_CREDENTIALS === 'true';
const isProduction = process.env.NODE_ENV === 'production';

const corsOptions = {
  origin: (origin, callback) => {
    // Allow requests with no origin (e.g., curl, server-to-server)
    if (!origin) return callback(null, true);
    // In non-production (development/testing), allow all origins
    if (!isProduction) return callback(null, true);
    // In production, check against allowed list
    if (!allowedOrigins) return callback(null, true); // allow all if no restrictions
    if (allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error('CORS origin denied'));
  },
  credentials: allowCredentials,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept'],
  exposedHeaders: ['Authorization', 'Content-Length', 'X-Request-Id'],
};
app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

// Ensure CORS headers are present on every response — helpful for debugging
app.use((req, res, next) => {
  const origin = req.headers.origin;

  // In non-production, echo back the origin or use wildcard
  if (!isProduction) {
    if (origin) {
      res.setHeader('Access-Control-Allow-Origin', origin);
    } else {
      res.setHeader('Access-Control-Allow-Origin', '*');
    }
  } else if (process.env.ALLOWED_ORIGINS) {
    // In production with explicit origins, only echo back allowed origins
    const allowed = process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim());
    if (origin && allowed.includes(origin)) {
      res.setHeader('Access-Control-Allow-Origin', origin);
    }
  } else {
    // Default to wildcard in production without restrictions
    res.setHeader('Access-Control-Allow-Origin', '*');
  }

  res.setHeader('Access-Control-Allow-Headers', (corsOptions.allowedHeaders || []).join(','));
  res.setHeader('Access-Control-Allow-Methods', (corsOptions.methods || []).join(','));

  // Do not set Access-Control-Allow-Credentials unless explicitly required
  if (process.env.ALLOW_CREDENTIALS === 'true') {
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }

  // Short-circuit OPTIONS requests with OK so preflight always succeeds
  if (req.method === 'OPTIONS') return res.sendStatus(204);

  next();
});

// Body parser
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Debugging incoming requests
app.use((req, res, next) => {
  console.log('👉 Request Origin:', req.headers.origin || 'No origin');
  next();
});

// Log response headers for auth endpoints to help debug missing CORS headers
app.use((req, res, next) => {
  // Only attach for auth-related paths to reduce noise
  const shouldLog = req.path.startsWith('/api/auth') || req.path === '/api/auth' || req.path === '/auth';
  if (shouldLog) {
    res.on('finish', () => {
      try {
        const headers = res.getHeaders ? res.getHeaders() : '(no headers)';
        console.log(`📤 Response for ${req.method} ${req.originalUrl} — status ${res.statusCode}`);
        console.log('📤 Response headers:', headers);
      } catch (err) {
        console.error('Failed to read response headers for logging', err && err.message ? err.message : err);
      }
    });
  }
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
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Health check
app.get('/api/health', (req, res) => {
  res.json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV
  });
});

// Email service - require after app is configured
const emailService = require('./utils/emailService');

// Liveness: service process is alive
app.get('/health', (req, res) => {
  res.json({ status: 'UP', timestamp: new Date().toISOString() });
});

// Readiness: check external dependencies (MongoDB, optional email config)
app.get('/health/ready', (req, res) => {
  const dbState = mongoose.connection.readyState; // 1 = connected
  const dbConnected = dbState === 1;
  const emailConfigured = emailService && emailService.isConfigured;

  const details = {
    db: dbConnected ? 'connected' : `not-connected (state=${dbState})`,
    email: emailConfigured ? 'configured' : 'not-configured'
  };

  if (dbConnected) {
    return res.json({ status: 'READY', details, timestamp: new Date().toISOString() });
  }
  return res.status(503).json({ status: 'NOT_READY', details, timestamp: new Date().toISOString() });
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

// Attach error handler to surface port binding problems clearly
server.on('error', (err) => {
  if (err && err.code === 'EADDRINUSE') {
    console.error('FATAL: Port already in use:', PORT);
    console.error('This prevents the server from starting. Ensure no other process is listening on this port, or change `PORT` in your environment.');
    process.exit(1);
  }
  console.error('Server error during startup:', err);
  process.exit(1);
});

// Startup sequence: wait for DB, then start server
const startServer = async () => {
  try {
    const conn = await connectDB();
    console.log('✅ Database connection established, proceeding with server startup');

    // Set up periodic activity tracking
    const User = require('./models/User');
    const publishActivityUpdate = global.publishActivityUpdate || (async (payload) => {
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

    // Start periodic job only after DB connected
    setInterval(emitActiveCounts, 15 * 1000);
    emitActiveCounts();

    // Start listening only after DB is connected
    server.listen(PORT, HOST, () => {
      console.log(`🚀 Server running on ${HOST}:${PORT}`);
      console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
    });

  } catch (err) {
    // Log full error so App Runner / platform logs contain the cause
    console.error('FATAL: Database connection failed during startup:', err && err.stack ? err.stack : err);
    logger.errorLog(err, { context: 'Startup - DB connection failed' });
    // Exit with non-zero so platform can detect failure and surface logs
    process.exit(1);
  }
};

// Only start if running directly (not imported as module)
if (require.main === module) {
  startServer();
}

// Crash handlers so we can see errors in logs and let the platform restart the container
process.on('uncaughtException', (err) => {
  console.error('UNCAUGHT EXCEPTION:', err && err.stack ? err.stack : err);
  process.exit(1);
});
process.on('unhandledRejection', (reason) => {
  console.error('UNHANDLED REJECTION:', reason);
  process.exit(1);
});

// Export for AWS Lambda with proper Express app support
// This wraps the Express app to handle Lambda events
module.exports.handler = serverless(app, {
  request: (request, event, context) => {
    // Pass event and context to app for debugging if needed
    request.context = { event, context };
  },
  response: (response, event, context) => {
    // Ensure proper CORS headers in response
    if (!response.headers) {
      response.headers = {};
    }
    // Mirror runtime CORS settings to Lambda responses
    const allowedOriginsEnv = process.env.ALLOWED_ORIGINS;
    const allowedOrigins = allowedOriginsEnv ? allowedOriginsEnv.split(',').map(s => s.trim()) : null;
    const allowCredentials = process.env.ALLOW_CREDENTIALS === 'true';

    // If allowedOrigins is set, use the request origin if allowed; otherwise use wildcard
    const origin = (event && event.headers && (event.headers.origin || event.headers.Origin)) || '*';
    if (allowedOrigins && origin && allowedOrigins.includes(origin)) {
      response.headers['Access-Control-Allow-Origin'] = origin;
    } else if (!allowedOrigins) {
      response.headers['Access-Control-Allow-Origin'] = '*';
    }

    response.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization,X-Requested-With,Accept';
    response.headers['Access-Control-Allow-Methods'] = 'OPTIONS,POST,GET,PUT,PATCH,DELETE';
    if (allowCredentials) response.headers['Access-Control-Allow-Credentials'] = 'true';
  }
});
