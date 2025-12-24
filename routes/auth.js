const express = require('express');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const User = require('../models/User');
const emailService = require('../utils/emailService');
const { auth } = require('../middleware/auth');
const { body, validationResult } = require('express-validator');
const logger = require('../middleware/logger');

const router = express.Router();

// Login
router.post('/login', [
  body('email').isEmail().normalizeEmail(),
  body('password').exists()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn('Login validation failed', { errors: errors.array() });
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;
    
    logger.info('Login attempt', { email });
    
    const user = await User.findOne({ email, isActive: true }).populate('collegeId');
    if (!user) {
      logger.warn('Login failed - user not found', { email });
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      logger.warn('Login failed - invalid password', { email, userId: user._id });
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    // Update login tracking
  user.lastLogin = new Date();
  user.hasLoggedIn = true;
  user.loginCount = (user.loginCount || 0) + 1;
  await user.save();

    logger.authLog('LOGIN_SUCCESS', user, { ip: req.ip });

    const token = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    const userResponse = {
      id: user._id,
      name: user.name,
      email: user.email,
      role: user.role,
      collegeId: user.collegeId?._id,
      collegeName: user.collegeId?.name,
      hasLoggedIn: user.hasLoggedIn,
      lastLogin: user.lastLogin
    };

    logger.info('Login successful', { 
      userId: user._id, 
      email: user.email, 
      role: user.role 
    });

    res.json({ token, user: userResponse });
  } catch (error) {
    logger.errorLog(error, { context: 'User Login', email: req.body.email });
    res.status(500).json({ error: 'Server error' });
  }
});

// Get current user
router.get('/me', auth, async (req, res) => {
  try {
    logger.info('Get current user request', { userId: req.user._id });
    
    const user = await User.findById(req.user._id)
      .select('-password')
      .populate('collegeId');
    
    res.json(user);
  } catch (error) {
    logger.errorLog(error, { context: 'Get Current User', userId: req.user?._id });
    res.status(500).json({ error: 'Server error' });
  }
});

// Update profile
router.put('/profile', auth, [
  body('name').trim().isLength({ min: 2 }),
  body('phoneNumber').optional().trim(),
  body('branch').optional().trim(),
  body('batch').optional().trim(),
  body('section').optional().trim(),
  body('companyName').optional().trim(),
  body('companyAddress').optional().trim()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn('Profile update validation failed', {
        userId: req.user._id,
        errors: errors.array()
      });
      return res.status(400).json({ errors: errors.array() });
    }

    logger.info('Profile update request', { userId: req.user._id });

    const updates = {};
    const allowedFields = ['name', 'phoneNumber', 'branch', 'batch', 'section', 'companyName', 'companyAddress'];

    allowedFields.forEach(field => {
      if (req.body[field] !== undefined) {
        updates[field] = req.body[field];
      }
    });

    const user = await User.findByIdAndUpdate(
      req.user._id,
      updates,
      { new: true, runValidators: true }
    ).select('-password');

    logger.info('Profile updated successfully', {
      userId: req.user._id,
      updatedFields: Object.keys(updates)
    });

    res.json(user);
  } catch (error) {
    logger.errorLog(error, { context: 'Profile Update', userId: req.user?._id });
    res.status(500).json({ error: 'Server error' });
  }
});

// Refresh token
router.post('/refresh-token', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).populate('collegeId');
    if (!user || !user.isActive) {
      return res.status(401).json({ error: 'User not found or inactive' });
    }

    const newToken = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    logger.info('Token refreshed', { userId: user._id });
    res.json({ token: newToken });
  } catch (error) {
    logger.errorLog(error, { context: 'Token Refresh', userId: req.user?._id });
    res.status(500).json({ error: 'Server error' });
  }
});

// Change password
router.put('/change-password', auth, [
  body('currentPassword').exists(),
  body('newPassword').isLength({ min: 6 })
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn('Change password validation failed', { 
        userId: req.user._id, 
        errors: errors.array() 
      });
      return res.status(400).json({ errors: errors.array() });
    }

    logger.info('Change password request', { userId: req.user._id });

    const { currentPassword, newPassword } = req.body;
    
    const user = await User.findById(req.user._id);
    const isMatch = await user.comparePassword(currentPassword);
    
    if (!isMatch) {
      logger.warn('Change password failed - incorrect current password', { 
        userId: req.user._id 
      });
      return res.status(400).json({ error: 'Current password is incorrect' });
    }

    user.password = newPassword;
    await user.save();

    logger.authLog('PASSWORD_CHANGED', user);

    res.json({ message: 'Password updated successfully' });
  } catch (error) {
    logger.errorLog(error, { context: 'Change Password', userId: req.user?._id });
    res.status(500).json({ error: 'Server error' });
  }
});

// Request password reset
router.post('/forgot-password', [
  body('email').isEmail().normalizeEmail()
], async (req, res) => {
  try {
    const { email } = req.body;
    
    logger.info('Forgot password request', { email });
    
    const user = await User.findOne({ email, isActive: true });
    if (!user) {
      logger.warn('Forgot password - user not found', { email });
      return res.status(404).json({ error: 'User not found' });
    }

    const resetToken = user.generateResetToken();
    await user.save();

    logger.info('Password reset token generated', { 
      userId: user._id, 
      email: user.email 
    });

    const emailResult = await emailService.sendPasswordReset(
      user.email,
      user.name,
      resetToken
    );

    if (emailResult.success) {
      logger.info('Password reset email sent successfully', {
        userId: user._id,
        email: user.email
      });
      res.json({
        message: 'Password reset email sent successfully. Please check your email.'
      });
    } else {
      logger.error('Failed to send password reset email', {
        userId: user._id,
        email: user.email,
        error: emailResult.error
      });
      res.status(500).json({
        error: 'Failed to send password reset email. Please try again later.',
        details: emailResult.error
      });
    }
  } catch (error) {
    logger.errorLog(error, { context: 'Forgot Password', email: req.body.email });
    res.status(500).json({ error: 'Server error' });
  }
});

// Reset password
router.post('/reset-password/:token', [
  body('password').isLength({ min: 6 })
], async (req, res) => {
  try {
    const { token } = req.params;
    const { password } = req.body;

    logger.info('Password reset attempt', { token: token.substring(0, 10) + '...' });

    const hashedToken = crypto
      .createHash('sha256')
      .update(token)
      .digest('hex');

    const user = await User.findOne({
      resetPasswordToken: hashedToken,
      resetPasswordExpires: { $gt: Date.now() }
    });

    if (!user) {
      logger.warn('Password reset failed - invalid or expired token', { token });
      return res.status(400).json({ error: 'Invalid or expired reset token' });
    }

    user.password = password;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    logger.authLog('PASSWORD_RESET', user);

    res.json({ message: 'Password reset successfully' });
  } catch (error) {
    logger.errorLog(error, { context: 'Password Reset', token: req.params.token });
    res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;