const mongoose = require('mongoose');

const notificationRecipientSchema = new mongoose.Schema({
  notificationId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Notification',
    required: true
  },
  recipientId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  recipientRole: {
    type: String,
    enum: ['college_admin', 'faculty', 'student'],
    required: true
  },
  collegeId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'College',
    required: true
  },
  // Status tracking
  isRead: {
    type: Boolean,
    default: false
  },
  readAt: Date,
  emailSent: {
    type: Boolean,
    default: false
  },
  emailSentAt: Date,
  // Delivery status
  deliveryStatus: {
    type: String,
    enum: ['pending', 'delivered', 'failed'],
    default: 'pending'
  }
}, {
  timestamps: true
});

// Compound indexes for efficient queries
notificationRecipientSchema.index({ recipientId: 1, createdAt: -1 });
notificationRecipientSchema.index({ notificationId: 1, recipientId: 1 }, { unique: true });
notificationRecipientSchema.index({ recipientId: 1, isRead: 1 });
notificationRecipientSchema.index({ collegeId: 1, createdAt: -1 });

module.exports = mongoose.model('NotificationRecipient', notificationRecipientSchema);