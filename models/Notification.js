const mongoose = require('mongoose');

const notificationSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true,
    trim: true
  },
  message: {
    type: String,
    required: true,
    trim: true
  },
  type: {
    type: String,
    enum: ['general', 'urgent', 'announcement', 'reminder'],
    default: 'general'
  },
  priority: {
    type: String,
    enum: ['low', 'medium', 'high'],
    default: 'medium'
  },
  // Who created the notification
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  createdByRole: {
    type: String,
    enum: ['master_admin', 'college_admin'],
    required: true
  },
  // Target audience
  targetType: {
    type: String,
    enum: ['colleges', 'faculty', 'students', 'specific'],
    required: true
  },
  // For college-specific notifications
  collegeId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'College'
  },
  // Specific targets
  targetColleges: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'College'
  }],
  targetUsers: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }],
  // Filters for students/faculty
  filters: {
    branches: [String],
    batches: [String],
    sections: [String],
    roles: [String]
  },
  // File attachment
  attachment: {
    filename: String,
    originalName: String,
    mimetype: String,
    size: Number,
    path: String
  },
  attachmentUrl: String,
  // Scheduling
  scheduledFor: {
    type: Date,
    default: Date.now
  },
  expiresAt: Date,
  // Status
  isActive: {
    type: Boolean,
    default: true
  },
  // Statistics
  totalRecipients: {
    type: Number,
    default: 0
  },
  emailsSent: {
    type: Number,
    default: 0
  }
}, {
  timestamps: true
});

// Index for efficient queries
notificationSchema.index({ createdBy: 1, createdAt: -1 });
notificationSchema.index({ collegeId: 1, createdAt: -1 });
notificationSchema.index({ scheduledFor: 1, isActive: 1 });

module.exports = mongoose.model('Notification', notificationSchema);