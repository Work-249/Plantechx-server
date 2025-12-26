/**
 * Security Middleware
 * Provides input validation, sanitization, rate limiting, and CSRF protection
 */

const crypto = require('crypto');
const validator = require('validator');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');
const helmet = require('helmet');

// =============== INPUT SANITIZATION & VALIDATION ===============

/**
 * Sanitize string inputs to prevent XSS and injection attacks
 */
const sanitizeInput = (input) => {
  if (typeof input !== 'string') return input;
  
  // Remove dangerous characters and trim
  return validator.trim(validator.escape(input));
};

/**
 * Sanitize code input with restrictions
 * - Max length limits
 * - Dangerous keyword detection
 */
const sanitizeCodeInput = (code, maxLength = 50000) => {
  if (typeof code !== 'string') {
    throw new Error('Code must be a string');
  }

  // Check code length
  if (code.length > maxLength) {
    throw new Error(`Code exceeds maximum length of ${maxLength} characters`);
  }

  // Dangerous patterns to block
  const dangerousPatterns = [
    /require\s*\(\s*['"`]fs['"`]\s*\)/gi,           // File system access
    /require\s*\(\s*['"`]os['"`]\s*\)/gi,           // OS access
    /require\s*\(\s*['"`]child_process['"`]\s*\)/gi, // Process execution
    /require\s*\(\s*['"`]net['"`]\s*\)/gi,          // Network access
    /require\s*\(\s*['"`]http['"`]\s*\)/gi,         // HTTP access
    /eval\s*\(/gi,                                  // Eval execution
    /Function\s*\(/gi,                              // Function constructor
    /import\s+.*from\s+['"`].*['"`]/gi,             // Dynamic imports
    /__dirname/gi,                                  // Directory path access
    /__filename/gi,                                 // File path access
  ];

  for (const pattern of dangerousPatterns) {
    if (pattern.test(code)) {
      throw new Error('Code contains prohibited patterns or system access attempts');
    }
  }

  return code;
};

/**
 * Validate email format
 */
const validateEmail = (email) => {
  if (!validator.isEmail(email)) {
    throw new Error('Invalid email format');
  }
  return validator.normalizeEmail(email);
};

/**
 * Validate password strength
 */
const validatePassword = (password) => {
  if (!password || password.length < 8) {
    throw new Error('Password must be at least 8 characters long');
  }
  if (!/[A-Z]/.test(password)) {
    throw new Error('Password must contain at least one uppercase letter');
  }
  if (!/[a-z]/.test(password)) {
    throw new Error('Password must contain at least one lowercase letter');
  }
  if (!/[0-9]/.test(password)) {
    throw new Error('Password must contain at least one digit');
  }
  if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
    throw new Error('Password must contain at least one special character');
  }
  return true;
};

/**
 * Validate language (limit supported languages)
 */
const validateLanguage = (language) => {
  const supportedLanguages = ['javascript', 'python'];
  if (!supportedLanguages.includes(language?.toLowerCase())) {
    throw new Error(`Language must be one of: ${supportedLanguages.join(', ')}`);
  }
  return language.toLowerCase();
};

/**
 * Sanitize object recursively
 */
const sanitizeObject = (obj) => {
  if (obj === null || obj === undefined) return obj;
  
  if (Array.isArray(obj)) {
    return obj.map(item => sanitizeObject(item));
  }
  
  if (typeof obj === 'object') {
    const sanitized = {};
    for (const key in obj) {
      if (obj.hasOwnProperty(key)) {
        sanitized[key] = sanitizeObject(obj[key]);
      }
    }
    return sanitized;
  }
  
  if (typeof obj === 'string') {
    return sanitizeInput(obj);
  }
  
  return obj;
};

// =============== CSRF TOKEN MANAGEMENT ===============

/**
 * Generate CSRF token
 */
const generateCSRFToken = () => {
  return crypto.randomBytes(32).toString('hex');
};

/**
 * Create CSRF token middleware
 * Generates token and stores in session/response
 */
const csrfProtection = (req, res, next) => {
  if (!req.session) {
    req.session = {};
  }
  
  if (!req.session.csrfToken) {
    req.session.csrfToken = generateCSRFToken();
  }
  
  res.locals.csrfToken = req.session.csrfToken;
  next();
};

/**
 * Verify CSRF token middleware
 * For POST, PUT, PATCH, DELETE requests
 */
const verifyCsrfToken = (req, res, next) => {
  // Skip CSRF check for GET, OPTIONS requests
  if (['GET', 'OPTIONS', 'HEAD'].includes(req.method)) {
    return next();
  }

  const token = req.headers['x-csrf-token'] || req.body?.csrfToken;
  const sessionToken = req.session?.csrfToken;

  if (!token || token !== sessionToken) {
    return res.status(403).json({ error: 'CSRF token validation failed' });
  }

  next();
};

// =============== RATE LIMITING FOR CODE EXECUTION ===============

/**
 * Advanced rate limiter for code execution endpoints
 * More restrictive than general API rate limiting
 */
const createCodeExecutionLimiter = (rateLimit) => {
  return rateLimit({
    windowMs: 60 * 1000,        // 1 minute
    max: 10,                     // Max 10 requests per minute
    message: 'Too many code execution requests. Please wait before trying again.',
    skipSuccessfulRequests: false,
    skipFailedRequests: false,
    standardHeaders: true,
    legacyHeaders: false,
  });
};

/**
 * Input validation middleware for coding submission
 */
const validateCodingSubmission = (req, res, next) => {
  try {
    const { code, language, questionId } = req.body;

    // Validate required fields
    if (!code || typeof code !== 'string') {
      return res.status(400).json({ error: 'Code is required and must be a string' });
    }

    if (!language || typeof language !== 'string') {
      return res.status(400).json({ error: 'Language is required' });
    }

    if (!questionId) {
      return res.status(400).json({ error: 'Question ID is required' });
    }

    // Validate and sanitize inputs
    try {
      req.body.code = sanitizeCodeInput(code, 50000); // 50KB max
      req.body.language = validateLanguage(language);
    } catch (error) {
      return res.status(400).json({ error: error.message });
    }

    next();
  } catch (error) {
    res.status(400).json({ error: 'Invalid submission data' });
  }
};

/**
 * Input validation middleware for question creation/update
 */
const validateQuestionInput = (req, res, next) => {
  try {
    const { title, description, difficulty, tags, testCases } = req.body;

    // Validate required fields
    if (!title || typeof title !== 'string' || title.length < 3) {
      return res.status(400).json({ error: 'Title must be at least 3 characters' });
    }

    if (title.length > 200) {
      return res.status(400).json({ error: 'Title must not exceed 200 characters' });
    }

    if (description && description.length > 10000) {
      return res.status(400).json({ error: 'Description must not exceed 10000 characters' });
    }

    if (difficulty && !['easy', 'medium', 'hard'].includes(difficulty)) {
      return res.status(400).json({ error: 'Invalid difficulty level' });
    }

    if (tags && Array.isArray(tags)) {
      if (tags.length > 20) {
        return res.status(400).json({ error: 'Maximum 20 tags allowed' });
      }
      for (const tag of tags) {
        if (typeof tag !== 'string' || tag.length > 50) {
          return res.status(400).json({ error: 'Invalid tag format' });
        }
      }
    }

    // Validate test cases
    if (testCases && Array.isArray(testCases)) {
      if (testCases.length > 100) {
        return res.status(400).json({ error: 'Maximum 100 test cases allowed' });
      }
      
      for (const tc of testCases) {
        if (!tc.input || typeof tc.input !== 'string' || tc.input.length > 10000) {
          return res.status(400).json({ error: 'Test case input exceeds limits' });
        }
        if (!tc.expected_output || typeof tc.expected_output !== 'string' || tc.expected_output.length > 10000) {
          return res.status(400).json({ error: 'Test case output exceeds limits' });
        }
      }
    }

    // Sanitize inputs
    req.body.title = sanitizeInput(req.body.title);
    if (req.body.description) {
      req.body.description = sanitizeInput(req.body.description);
    }
    if (req.body.tags) {
      req.body.tags = req.body.tags.map(tag => sanitizeInput(tag));
    }

    next();
  } catch (error) {
    res.status(400).json({ error: 'Invalid input data' });
  }
};

// =============== REQUEST SIZE & TIMEOUT LIMITS ===============

/**
 * Configure global request size limits
 */
const requestSizeLimits = {
  json: '10mb',
  urlencoded: '10mb',
  text: '10mb',
};

/**
 * Request timeout middleware
 */
// D:\plantex\Plantechx-server\middleware\security.js

const requestTimeout = (timeout = 30000) => {
  return (req, res, next) => {
    res.setTimeout(timeout, () => {
      // Check if headers were already sent to prevent the crash
      if (!res.headersSent) {
        res.status(408).json({ error: 'Request timeout' });
      }
    });
    next();
  };
};
// =============== SECURITY HEADERS MIDDLEWARE ===============

/**
 * Additional security headers
 */
const securityHeaders = (req, res, next) => {
  // Prevent MIME type sniffing
  res.setHeader('X-Content-Type-Options', 'nosniff');
  
  // Prevent clickjacking
  res.setHeader('X-Frame-Options', 'DENY');
  
  // Enable XSS protection
  res.setHeader('X-XSS-Protection', '1; mode=block');
  
  // Content Security Policy
  res.setHeader('Content-Security-Policy', 
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'");
  
  // Referrer Policy
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  
  // Feature Policy
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  
  next();
};

// =============== REQUEST LOGGING & MONITORING ===============

/**
 * Log suspicious requests
 */
const logSuspiciousRequest = (req, res, next) => {
  const suspiciousPatterns = [
    /['"`]/,          // Quotes that might indicate injection
    /(\.\.)|(\/\/)/,  // Path traversal
    /union|select|insert|update|delete|drop/i, // SQL keywords
  ];

  const bodyStr = JSON.stringify(req.body || {});
  const queryStr = JSON.stringify(req.query || {});
  
  for (const pattern of suspiciousPatterns) {
    if (pattern.test(bodyStr) || pattern.test(queryStr)) {
      console.warn('[SECURITY] Suspicious request detected:', {
        method: req.method,
        path: req.path,
        ip: req.ip,
        timestamp: new Date().toISOString()
      });
      break;
    }
  }
  
  next();
};

module.exports = {
  // Sanitization
  sanitizeInput,
  sanitizeCodeInput,
  sanitizeObject,
  
  // Validation
  validateEmail,
  validatePassword,
  validateLanguage,
  validateCodingSubmission,
  validateQuestionInput,
  
  // CSRF
  generateCSRFToken,
  csrfProtection,
  verifyCsrfToken,
  
  // Rate Limiting
  createCodeExecutionLimiter,
  
  // Request handling
  requestSizeLimits,
  requestTimeout,
  
  // Security Headers
  securityHeaders,
  
  // Monitoring
  logSuspiciousRequest,
};
