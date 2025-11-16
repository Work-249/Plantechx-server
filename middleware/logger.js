const fs = require('fs');
const path = require('path');

// Logs directory
const logsDir = process.env.VERCEL ? '/tmp/logs' : path.join(__dirname, '../logs');
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir, { recursive: true });
}

// Log levels
const LOG_LEVELS = {
  ERROR: 0,
  WARN: 1,
  INFO: 2,
  DEBUG: 3
};

class Logger {
  constructor() {
    this.logLevel = process.env.LOG_LEVEL || 'INFO';
    // Whether to mask PII (emails) in logs. Set MASK_PII=false to disable masking (useful for local debug).
    this.maskingEnabled = (typeof process.env.MASK_PII === 'undefined') ? true : (String(process.env.MASK_PII).toLowerCase() !== 'false');
  }

  // Mask email helper for logs (e.g. j***@domain.com)
  maskEmail(email) {
    if (!this.maskingEnabled) return email || 'N/A';
    try {
      if (!email || typeof email !== 'string') return 'N/A';
      const parts = email.split('@');
      if (parts.length !== 2) return '***';
      const local = parts[0];
      const domain = parts[1];
      const visibleLocal = local.length > 0 ? local[0] : '*';
      return `${visibleLocal}***@${domain}`;
    } catch (e) {
      return '***';
    }
  }

  // Sanitize meta object to remove or mask PII like emails
  sanitizeMeta(meta = {}) {
    const copy = { ...meta };
    if (!this.maskingEnabled) return copy;
    if (copy.userEmail) copy.userEmail = this.maskEmail(copy.userEmail);
    if (copy.email) copy.email = this.maskEmail(copy.email);
    if (copy.to) copy.to = this.maskEmail(copy.to);
    return copy;
  }

  // Format log message
  formatMessage(level, message, meta = {}) {
    const timestamp = new Date().toISOString();
    return JSON.stringify({ timestamp, level, message, ...meta }) + '\n';
  }

  // Write log to file
  writeToFile(filename, content) {
    try {
      fs.appendFileSync(path.join(logsDir, filename), content);
    } catch (err) {
      // Avoid calling logger here (would recurse). Use stderr directly so logger write failures
      // are still visible without triggering the logger flow.
      try {
        process.stderr.write(`[LOGGER ERROR] Failed to write log file: ${err.message}\n`);
      } catch (e) {
        // Last-resort: if stderr write fails, use console.error as an unavoidable fallback.
        console.error('LOGGER FATAL - failed to write to stderr or log file:', err.message);
      }
    }
  }

  // Main logging function
  log(level, message, meta = {}) {
    if (LOG_LEVELS[level] <= LOG_LEVELS[this.logLevel]) {
      const safeMeta = this.sanitizeMeta(meta);
      const formattedMessage = this.formatMessage(level, message, safeMeta);

      // Console output with colors
      const colors = {
        ERROR: '\x1b[31m', // Red
        WARN: '\x1b[33m',  // Yellow
        INFO: '\x1b[36m',  // Cyan
        DEBUG: '\x1b[37m'  // White
      };
      console.log(`${colors[level]}[${level}] ${new Date().toISOString()} - ${message}\x1b[0m`, safeMeta);

      // Write to files
      this.writeToFile(`${level.toLowerCase()}.log`, formattedMessage);
      this.writeToFile('combined.log', formattedMessage);
    }
  }

  error(message, meta = {}) { this.log('ERROR', message, meta); }
  warn(message, meta = {}) { this.log('WARN', message, meta); }
  info(message, meta = {}) { this.log('INFO', message, meta); }
  debug(message, meta = {}) { this.log('DEBUG', message, meta); }

  // Express request logger middleware
  requestLogger() {
    return (req, res, next) => {
      const start = Date.now();
      const { method, url, ip, headers } = req;

      this.info('Incoming Request', {
        method,
        url,
        ip,
        userAgent: headers['user-agent'],
        contentType: headers['content-type'],
        authorization: headers.authorization ? 'Bearer ***' : 'None',
        body: ['POST', 'PUT'].includes(req.method) ? this.sanitizeBody(req.body) : undefined
      });

      const originalJson = res.json;
      res.json = (data) => {
        const duration = Date.now() - start;
        this.info('Outgoing Response', {
          method,
          url,
          statusCode: res.statusCode,
          duration: `${duration}ms`,
          responseSize: JSON.stringify(data).length
        });
        return originalJson.call(res, data);
      };

      next();
    };
  }

  // Remove sensitive fields from request body or data
  sanitizeBody(body) {
    if (!body) return body;
    const sanitized = { ...body };
    const sensitiveFields = ['password', 'token', 'secret', 'key'];
    sensitiveFields.forEach(field => { if (sanitized[field]) sanitized[field] = '***'; });
    return sanitized;
  }

  // Log DB operations
  dbLog(operation, collection, query = {}, result = {}) {
    this.info('Database Operation', {
      operation,
      collection,
      query: this.sanitizeBody(query),
      resultCount: result.length || (result._id ? 1 : 0),
      executionTime: result.executionTime || 'N/A'
    });
  }

  // Log authentication events
  authLog(event, user = {}, meta = {}) {
    const base = {
      event,
      userId: user._id || user.id,
      userRole: user.role,
      ...meta
    };
    if (user.email) base.userEmail = this.maskEmail(user.email);
    this.info('Authentication Event', this.sanitizeMeta(base));
  }

  // Log errors with stack trace
  errorLog(error, context = {}) {
    const ctx = Object.assign({ message: error.message, stack: error.stack, name: error.name }, context);
    this.error('Application Error', this.sanitizeMeta(ctx));
  }
}

const logger = new Logger();
module.exports = logger;
