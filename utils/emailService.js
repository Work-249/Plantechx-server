const nodemailer = require('nodemailer');
const logger = require('../middleware/logger');
const PendingEmail = require('../models/PendingEmail');

class EmailService {
  constructor() {
    // Use centralized logger masking helpers
    // emailService will call logger.maskEmail and logger.sanitizeMeta when preparing logs

    const emailPort = parseInt(process.env.EMAIL_PORT || '587', 10);
    const isSecure = emailPort === 465;
    const environment = process.env.NODE_ENV || 'development';

    logger.info('Initializing Email Service', {
      host: process.env.EMAIL_HOST || 'smtp.gmail.com',
      port: emailPort,
      secure: isSecure,
      environment,
      user: process.env.EMAIL_USER ? 'Configured' : 'Not configured'
    });

    this.transporter = nodemailer.createTransport({
      host: process.env.EMAIL_HOST || 'smtp.gmail.com',
      port: emailPort,
      secure: isSecure,
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
      },
      connectionTimeout: 15000,
      greetingTimeout: 15000,
      socketTimeout: 15000,
      pool: true,
      maxConnections: 5,
      maxMessages: 100,
      requireTLS: !isSecure,
      tls: {
        rejectUnauthorized: environment === 'production',
        minVersion: 'TLSv1.2'
      },
      debug: environment === 'development',
      logger: environment === 'development'
    });

    this.maxRetries = 3;
    this.retryDelay = 2000;
    this.isConfigured = !!(process.env.EMAIL_USER && process.env.EMAIL_PASS);

    // Skip verification to avoid timeouts during startup; verification will happen on first send attempt
    if (this.isConfigured) {
      logger.info('Email service ready (verification deferred)');
    } else {
      logger.warn('Email service not configured - missing EMAIL_USER or EMAIL_PASS environment variables');
    }
  }

  // Basic email validation to catch obvious malformed addresses
  isValidEmail(email) {
    if (!email || typeof email !== 'string') return false;
    const trimmed = email.trim();
    // Simple RFC-like regex that allows dots in local part
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(trimmed);
  }

  async verifyConnection() {
    try {
      await this.transporter.verify();
      logger.info('✓ Email service connection verified successfully');
    } catch (error) {
      logger.errorLog(error, {
        context: 'Email Service Connection Verification',
        host: process.env.EMAIL_HOST,
        port: process.env.EMAIL_PORT
      });
    }
  }

  async sendWithRetry(mailOptions, meta = {}, retries = this.maxRetries) {
    // Development/dev-shim: if EMAIL_FAKE is set, don't actually send email — simulate success.
    if (process.env.EMAIL_FAKE === 'true') {
      const fakeMessageId = `fake-${Date.now()}`;
      console.log(`[email][FAKE] Simulated send to ${String(mailOptions.to || '')} (messageId=${fakeMessageId})`);
      // Return a success-like object so callers behave as if email was sent
      return { success: true, attempt: 0, messageId: fakeMessageId };
    }
    if (!this.isConfigured) {
      logger.warn('Email service not configured - skipping email send', logger.sanitizeMeta(mailOptions));
      return {
        success: false,
        error: 'Email service not configured',
        attempts: 0
      };
    }

    for (let attempt = 1; attempt <= retries; attempt++) {
      // Plain console logging to make send attempts visible during development
      try {
        console.log(`[email] Sending to ${String(mailOptions.to || '')} (attempt ${attempt}/${retries})`);
        const info = await this.transporter.sendMail(mailOptions);
        logger.info('✓ Email sent successfully', Object.assign({}, logger.sanitizeMeta(mailOptions), { attempt, messageId: info.messageId }));
        console.log(`[email] Sent ✓ to ${String(mailOptions.to || '')} (messageId=${info.messageId})`);
        return { success: true, attempt, messageId: info.messageId };
      } catch (error) {
        console.error(`[email] Error sending to ${String(mailOptions.to || '')} (attempt ${attempt}/${retries}):`, error && error.message ? error.message : error);
        logger.errorLog(error, Object.assign({ context: 'Email send attempt', attempt, maxRetries: retries, errorCode: error && error.code, command: error && error.command }, logger.sanitizeMeta(mailOptions)));

        if (attempt < retries) {
          const delay = this.retryDelay * attempt;
          console.log(`[email] Retrying in ${delay}ms...`);
          logger.info(`Retrying email send in ${delay}ms...`, { attempt: attempt + 1, maxRetries: retries });
          await new Promise(resolve => setTimeout(resolve, delay));
        } else {
          // Persist failed email to PendingEmail collection (best-effort)
          try {
            const recipient = String(mailOptions.to || '').trim();
            const recipientName = meta.recipientName || (meta.data && meta.data.recipientName) || recipient.split('@')[0];
            await PendingEmail.create({
              type: meta.type || (meta.data && meta.data.type) || 'notification',
              recipientEmail: recipient,
              recipientName: recipientName,
              userId: meta.userId || undefined,
              data: Object.assign({ subject: mailOptions.subject }, meta.data || {}, { html: mailOptions.html }),
              status: 'failed',
              attempts: retries,
              lastAttemptAt: new Date(),
              error: error && error.message ? error.message : String(error)
            });
            logger.info('Persisted failed email to PendingEmail', { to: logger.maskEmail(recipient), type: meta.type || 'notification' });
            console.error(`[email] Persisted failed email for ${recipient}`);
          } catch (persistErr) {
            logger.errorLog(persistErr, { context: 'Persist failed email', to: logger.maskEmail(mailOptions.to) });
            console.error(`[email] Failed to persist failed email for ${String(mailOptions.to || '')}:`, persistErr && persistErr.message ? persistErr.message : persistErr);
          }

          return {
            success: false,
            error: error && error.message ? error.message : String(error),
            attempts: retries,
            errorCode: error && error.code
          };
        }
      }
    }
    return { success: false, error: 'Max retries exceeded', attempts: retries };
  }

  async sendLoginCredentials(userEmail, userName, password, role, collegeName = null) {
  logger.info('Sending login credentials email', { to: logger.maskEmail(userEmail), role, collegeName });

    if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
      logger.errorLog(new Error('Email configuration missing'), { context: 'Send Login Credentials' });
      return { success: false, error: 'Email not configured', email: this.maskEmail(userEmail), role };
    }

    const roleText = this.getRoleDisplayName(role);
    
    const toAddress = String(userEmail || '').trim();
    if (!this.isValidEmail(toAddress)) {
      logger.errorLog(new Error('Invalid recipient email'), { context: 'Send Login Credentials - invalid email', to: logger.maskEmail(userEmail) });
      return { success: false, error: 'Invalid recipient email' };
    }

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: toAddress,
      subject: `Login Credentials - ${roleText} Account Created`,
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <div style="background-color: #3B82F6; color: white; padding: 20px; text-align: center;">
            <h1>Plantechx</h1>
          </div>
          <div style="padding: 20px; background-color: #f9f9f9;">
            <h2>Welcome, ${userName}!</h2>
            <p>Your ${roleText} account has been created successfully.</p>
            ${collegeName ? `<p><strong>College:</strong> ${collegeName}</p>` : ''}
            
            <div style="background-color: white; padding: 15px; border-left: 4px solid #3B82F6; margin: 20px 0;">
              <h3>Login Credentials:</h3>
              <p><strong>Email:</strong> ${userEmail}</p>
              <p><strong>Password:</strong> ${password}</p>
            </div>
            
            <p style="color: #dc2626; font-weight: bold;">
              ⚠️ Please change your password after first login for security reasons.
            </p>
            
            <div style="text-align: center; margin: 30px 0;">
              <a href="${process.env.FRONTEND_URL}/login" 
                 style="background-color: #3B82F6; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block;">
                Login Now
              </a>
            </div>
          </div>
          <div style="background-color: #374151; color: white; text-align: center; padding: 10px;">
            <p>Plantechx © 2025</p>
          </div>
        </div>
      `
    };

    const result = await this.sendWithRetry(mailOptions, {
      type: 'login_credentials',
      recipientName: userName,
      userId: null,
      data: { email: userEmail, password, role, collegeName }
    });

    if (result.success) {
      return { success: true };
    } else {
      logger.errorLog(new Error(result.error), Object.assign({ context: 'Send Login Credentials Email', attempts: result.attempts }, logger.sanitizeMeta(mailOptions)));
      return {
        success: false,
        error: result.error,
        email: logger.maskEmail(userEmail),
        role,
        collegeName
      };
    }
  }

  async sendPasswordReset(userEmail, userName, resetToken) {
  logger.info('Sending password reset email', { to: logger.maskEmail(userEmail) });
    
    const toAddress = String(userEmail || '').trim();
    if (!this.isValidEmail(toAddress)) {
      logger.errorLog(new Error('Invalid recipient email'), { context: 'Send Password Reset - invalid email', to: logger.maskEmail(userEmail) });
      return { success: false, error: 'Invalid recipient email' };
    }

    const resetUrl = `${process.env.FRONTEND_URL}/reset-password/${resetToken}`;
    
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: toAddress,
      subject: 'Password Reset Request - Plantechx',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <div style="background-color: #3B82F6; color: white; padding: 20px; text-align: center;">
            <h1>Password Reset Request</h1>
          </div>
          <div style="padding: 20px; background-color: #f9f9f9;">
            <h2>Hello, ${userName}!</h2>
            <p>You requested a password reset for your Plantechx account.</p>
            
            <div style="text-align: center; margin: 30px 0;">
              <a href="${resetUrl}" 
                 style="background-color: #dc2626; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block;">
                Reset Password
              </a>
            </div>
            
            <p style="color: #6b7280; font-size: 14px;">
              This link will expire in 10 minutes. If you didn't request this reset, please ignore this email.
            </p>
          </div>
        </div>
      `
    };

    const result = await this.sendWithRetry(mailOptions, {
      type: 'password_reset',
      recipientName: userName,
      data: { resetUrl }
    });

    if (result.success) {
      return { success: true };
    } else {
      logger.errorLog(new Error(result.error), Object.assign({ context: 'Send Password Reset Email', attempts: result.attempts }, logger.sanitizeMeta(mailOptions)));
      return { success: false, error: result.error };
    }
  }

  getRoleDisplayName(role) {
    const roleNames = {
      master_admin: 'Master Administrator',
      college_admin: 'College Administrator',
      faculty: 'Faculty',
      student: 'Student'
    };
    return roleNames[role] || role;
  }

  async sendTestAssignmentNotification(collegeEmail, collegeAdminName, testName, collegeName, startDateTime, endDateTime) {
  logger.info('Sending test assignment notification', Object.assign({ testName, collegeName }, { to: logger.maskEmail(collegeEmail) }));
    
    const toAddress = String(collegeEmail || '').trim();
    if (!this.isValidEmail(toAddress)) {
      logger.errorLog(new Error('Invalid recipient email'), { context: 'Send Test Assignment - invalid email', to: logger.maskEmail(collegeEmail) });
      return { success: false, error: 'Invalid recipient email' };
    }

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: toAddress,
      subject: `New Test Assignment - ${testName}`,
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <div style="background-color: #3B82F6; color: white; padding: 20px; text-align: center;">
            <h1>Test Assignment Notification</h1>
          </div>
          <div style="padding: 20px; background-color: #f9f9f9;">
            <h2>Hello, ${collegeAdminName}!</h2>
            <p>A new test has been assigned to your college: <strong>${collegeName}</strong></p>
            
            <div style="background-color: white; padding: 15px; border-left: 4px solid #3B82F6; margin: 20px 0;">
              <h3>Test Details:</h3>
              <p><strong>Test Name:</strong> ${testName}</p>
              <p><strong>Start Date:</strong> ${new Date(startDateTime).toLocaleString()}</p>
              <p><strong>End Date:</strong> ${new Date(endDateTime).toLocaleString()}</p>
            </div>
            
            <p>Please log in to your dashboard to accept or reject this test assignment.</p>
            
            <div style="text-align: center; margin: 30px 0;">
              <a href="${process.env.FRONTEND_URL}/login" 
                 style="background-color: #3B82F6; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block;">
                View Dashboard
              </a>
            </div>
          </div>
          <div style="background-color: #374151; color: white; text-align: center; padding: 10px;">
            <p>Plantechx © 2025</p>
          </div>
        </div>
      `
    };

    const result = await this.sendWithRetry(mailOptions, {
      type: 'test_assignment',
      recipientName: collegeAdminName,
      data: { testName, collegeName, startDateTime, endDateTime }
    });

    if (result.success) {
      return { success: true };
    } else {
      logger.errorLog(new Error(result.error), Object.assign({ context: 'Send Test Assignment Email', attempts: result.attempts }, logger.sanitizeMeta(mailOptions)));
      return { success: false, error: result.error };
    }
  }

  async sendCollegeCreated(collegeEmail, collegeName, adminName, additionalInfo = {}) {
  logger.info('Sending college creation confirmation email', { to: logger.maskEmail(collegeEmail) });

    const toAddress = String(collegeEmail || '').trim();
    if (!this.isValidEmail(toAddress)) {
      logger.errorLog(new Error('Invalid recipient email'), { context: 'Send College Created - invalid email', to: logger.maskEmail(collegeEmail) });
      return { success: false, error: 'Invalid recipient email' };
    }

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: toAddress,
      subject: `Welcome to Academic Management - ${collegeName}`,
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <div style="background-color: #3B82F6; color: white; padding: 20px; text-align: center;">
            <h1>Welcome to Academic Management</h1>
          </div>
          <div style="padding: 20px; background-color: #f9f9f9;">
            <h2>Hello ${adminName || 'Administrator'}!</h2>
            <p>Your college <strong>${collegeName}</strong> has been successfully registered on the platform.</p>
            ${additionalInfo.signupMessage ? `<p>${additionalInfo.signupMessage}</p>` : ''}
            <div style="text-align: center; margin: 30px 0;">
              <a href="${process.env.FRONTEND_URL}/login" 
                 style="background-color: #3B82F6; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block;">
                Go to Dashboard
              </a>
            </div>
          </div>
          <div style="background-color: #374151; color: white; text-align: center; padding: 10px;">
            <p>Plantechx © 2025</p>
          </div>
        </div>
      `
    };

    const result = await this.sendWithRetry(mailOptions, {
      type: 'college_created',
      recipientName: adminName,
      data: Object.assign({ collegeName }, additionalInfo)
    });
    if (result.success) return { success: true };
    return { success: false, error: result.error };
  }

  async sendTestAssignmentToStudent(studentEmail, studentName, testName, startDateTime, endDateTime, duration) {
  logger.info('Sending test assignment to student', Object.assign({ testName }, { to: logger.maskEmail(studentEmail) }));
    
    const toAddress = String(studentEmail || '').trim();
    if (!this.isValidEmail(toAddress)) {
      logger.errorLog(new Error('Invalid recipient email'), { context: 'Send Test Assignment To Student - invalid email', to: logger.maskEmail(studentEmail) });
      return { success: false, error: 'Invalid recipient email' };
    }

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: toAddress,
      subject: `Test Assignment - ${testName}`,
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <div style="background-color: #3B82F6; color: white; padding: 20px; text-align: center;">
            <h1>Test Assignment</h1>
          </div>
          <div style="padding: 20px; background-color: #f9f9f9;">
            <h2>Hello, ${studentName}!</h2>
            <p>You have been assigned a new test to complete.</p>
            
            <div style="background-color: white; padding: 15px; border-left: 4px solid #3B82F6; margin: 20px 0;">
              <h3>Test Details:</h3>
              <p><strong>Test Name:</strong> ${testName}</p>
              <p><strong>Duration:</strong> ${duration} minutes</p>
              <p><strong>Available From:</strong> ${new Date(startDateTime).toLocaleString()}</p>
              <p><strong>Available Until:</strong> ${new Date(endDateTime).toLocaleString()}</p>
            </div>
            
            <p style="color: #dc2626; font-weight: bold;">
              ⚠️ Make sure you have a stable internet connection and sufficient time before starting the test.
            </p>
            
            <div style="text-align: center; margin: 30px 0;">
              <a href="${process.env.FRONTEND_URL}/login" 
                 style="background-color: #3B82F6; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block;">
                Take Test
              </a>
            </div>
          </div>
          <div style="background-color: #374151; color: white; text-align: center; padding: 10px;">
            <p>Plantechx © 2025</p>
          </div>
        </div>
      `
    };

    const result = await this.sendWithRetry(mailOptions, {
      type: 'test_assignment',
      recipientName: studentName,
      data: { testName, startDateTime, endDateTime, duration }
    });

    if (result.success) {
      return { success: true };
    } else {
      logger.errorLog(new Error(result.error), Object.assign({ context: 'Send Student Test Assignment Email', attempts: result.attempts }, logger.sanitizeMeta(mailOptions)));
      return { success: false, error: result.error };
    }
  }

  async sendNotificationEmail(userEmail, userName, title, message, type = 'general', priority = 'medium', attachment = null) {
    logger.info('Sending notification email', Object.assign({ title, type, priority }, { to: logger.maskEmail(userEmail) }));
    const toAddress = String(userEmail || '').trim();
    if (!this.isValidEmail(toAddress)) {
      logger.errorLog(new Error('Invalid recipient email'), { context: 'Send Notification - invalid email', to: logger.maskEmail(userEmail) });
      return { success: false, error: 'Invalid recipient email' };
    }

    const priorityColors = {
      low: '#10B981',
      medium: '#3B82F6', 
      high: '#EF4444'
    };
    
    const typeIcons = {
      general: '📢',
      urgent: '🚨',
      announcement: '📣',
      reminder: '⏰'
    };
    
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: toAddress,
      subject: `${typeIcons[type] || '📢'} ${title}`,
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <div style="background-color: ${priorityColors[priority]}; color: white; padding: 20px; text-align: center;">
            <h1>${typeIcons[type] || '📢'} Notification</h1>
          </div>
          <div style="padding: 20px; background-color: #f9f9f9;">
            <h2>Hello, ${userName}!</h2>
            <div style="background-color: white; padding: 15px; border-left: 4px solid ${priorityColors[priority]}; margin: 20px 0;">
              <h3 style="margin-top: 0; color: ${priorityColors[priority]};">${title}</h3>
              <div style="line-height: 1.6; color: #374151;">
                ${message.replace(/\n/g, '<br>')}
              </div>
            </div>
            
            <div style="background-color: #f3f4f6; padding: 10px; border-radius: 5px; margin: 20px 0;">
              <p style="margin: 0; font-size: 12px; color: #6b7280;">
                <strong>Type:</strong> ${type.charAt(0).toUpperCase() + type.slice(1)} | 
                <strong>Priority:</strong> ${priority.charAt(0).toUpperCase() + priority.slice(1)}
              </p>
            </div>
            
            <div style="text-align: center; margin: 30px 0;">
              <a href="${process.env.FRONTEND_URL}/login" 
                 style="background-color: ${priorityColors[priority]}; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block;">
                View in Dashboard
              </a>
            </div>
          </div>
          <div style="background-color: #374151; color: white; text-align: center; padding: 10px;">
            <p>Plantechx © 2025</p>
          </div>
        </div>
      `
    };

    // If an attachment is provided, include it
    if (attachment && (attachment.path || attachment.url)) {
      mailOptions.attachments = [
        {
          filename: attachment.originalName || (attachment.path ? require('path').basename(attachment.path) : 'attachment'),
          path: attachment.path || attachment.url
        }
      ];
    }

    const result = await this.sendWithRetry(mailOptions, {
      type: 'notification',
      recipientName: userName,
      data: { title, message, type, priority }
    });

    if (result.success) {
      return { success: true };
    } else {
      logger.errorLog(new Error(result.error), Object.assign({ context: 'Send Notification Email', attempts: result.attempts }, logger.sanitizeMeta(mailOptions)));
      return { success: false, error: result.error };
    }
  }
}

module.exports = new EmailService();
