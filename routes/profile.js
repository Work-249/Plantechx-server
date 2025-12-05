const express = require('express');
const router = express.Router();
const { auth, authorize } = require('../middleware/auth');
const User = require('../models/User');
const { body, validationResult } = require('express-validator');
const logger = require('../middleware/logger');
// WebSocket notifications removed for profile route to simplify deployment
const emailService = require('../utils/emailService');
const bcrypt = require('bcryptjs');

// Get Master Admin profile info
router.get('/profile', auth, authorize('master_admin'), async (req, res) => {
  try {
    const admin = await User.findById(req.user._id).select('-password');
    if (!admin) {
      return res.status(404).json({ error: 'Profile not found' });
    }
    res.json(admin);
  } catch (error) {
    logger.errorLog(error, { context: 'Get profile error' });
    res.status(500).json({ error: 'Server error' });
  }
});

// Update Master Admin profile
router.put('/profile', auth, authorize('master_admin'), [
  body('name').optional().trim().isLength({ min: 2 }),
  body('email').optional().isEmail().normalizeEmail(),
  body('phoneNumber').optional().isMobilePhone('any'),
  body('currentPassword').if(body('email').exists()).exists().trim(),
  body('newPassword').optional().isLength({ min: 8 })
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const admin = await User.findById(req.user._id);
    if (!admin) {
      return res.status(404).json({ error: 'Profile not found' });
    }

    // If email is being changed, verify current password
    if (req.body.email && req.body.email !== admin.email) {
      const isValidPassword = await bcrypt.compare(req.body.currentPassword, admin.password);
      if (!isValidPassword) {
        return res.status(400).json({ error: 'Current password is incorrect' });
      }

      // Check if new email is already in use
      const existingUser = await User.findOne({ email: req.body.email });
      if (existingUser) {
        return res.status(400).json({ error: 'Email is already in use' });
      }
    }

    // Update fields
    const updates = {};
    const allowedFields = ['name', 'email', 'phoneNumber'];
    allowedFields.forEach(field => {
      if (req.body[field] !== undefined) {
        updates[field] = req.body[field];
      }
    });

    // Handle password change
    if (req.body.newPassword) {
      const isValidPassword = await bcrypt.compare(req.body.currentPassword, admin.password);
      if (!isValidPassword) {
        return res.status(400).json({ error: 'Current password is incorrect' });
      }
      updates.password = await bcrypt.hash(req.body.newPassword, 12);
    }

    // Update profile
    const updatedAdmin = await User.findByIdAndUpdate(
      req.user._id,
      { 
        $set: updates,
        updatedAt: new Date()
      },
      { new: true, runValidators: true }
    ).select('-password');

    // If email was changed, send confirmation to both old and new addresses
    if (req.body.email && req.body.email !== admin.email) {
      await Promise.all([
        emailService.sendNotificationEmail(
          admin.email,
          admin.name,
          'Email Address Change Notification',
          `Your email address has been changed from ${admin.email} to ${req.body.email}.`,
          'important',
          'high'
        ),
        emailService.sendNotificationEmail(
          req.body.email,
          admin.name,
          'Email Address Change Confirmation',
          'Your email address has been successfully updated in the system.',
          'important',
          'high'
        )
      ]);
    }

    // WebSocket notification intentionally removed.

    res.json({
      message: 'Profile updated successfully',
      user: updatedAdmin
    });
  } catch (error) {
    logger.errorLog(error, { context: 'Update profile error' });
    res.status(500).json({ error: 'Server error' });
  }
});

// Get profile activity log
router.get('/profile/activity', auth, authorize('master_admin'), async (req, res) => {
  try {
    const admin = await User.findById(req.user._id);
    if (!admin) {
      return res.status(404).json({ error: 'Profile not found' });
    }

    // Get recent activity (login history, profile updates, etc.)
    const activity = {
      lastLogin: admin.lastLogin,
      loginHistory: admin.loginHistory || [],
      profileUpdates: admin.profileUpdates || []
    };

    res.json(activity);
  } catch (error) {
    logger.errorLog(error, { context: 'Get activity log error' });
    res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;