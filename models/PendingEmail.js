const mongoose = require('mongoose');

const pendingEmailSchema = new mongoose.Schema({
  type: {
    type: String,
    enum: ['login_credentials', 'password_reset', 'test_assignment', 'notification'],
    required: true
  },
  recipientEmail: {
    type: String,
    required: true
  },
  recipientName: {
    type: String,
    required: true
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  data: {
    type: mongoose.Schema.Types.Mixed,
    required: true
  },
  status: {
    type: String,
    enum: ['pending', 'sent', 'failed'],
    default: 'pending'
  },
  attempts: {
    type: Number,
    default: 0
  },
  lastAttemptAt: Date,
  error: String,
  sentAt: Date
}, {
  timestamps: true
});

pendingEmailSchema.index({ status: 1, createdAt: -1 });
pendingEmailSchema.index({ recipientEmail: 1 });
pendingEmailSchema.index({ type: 1, status: 1 });

module.exports = mongoose.model('PendingEmail', pendingEmailSchema);
