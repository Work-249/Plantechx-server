const mongoose = require('mongoose');

const testAssignmentSchema = new mongoose.Schema({
  testId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Test',
    required: true
  },
  collegeId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'College',
    required: true
  },
  assignedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  assignedTo: {
    type: String,
    enum: ['college', 'students'],
    required: true
  },
  // For student-specific assignments
  studentFilters: {
    branches: [String],
    batches: [String],
    sections: [String],
    specificStudents: [{
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    }]
  },
  status: {
    type: String,
    enum: ['pending', 'accepted', 'rejected'],
    default: 'pending'
  },
  assignedAt: {
    type: Date,
    default: Date.now
  },
  acceptedAt: Date,
  rejectedAt: Date,
  isActive: {
    type: Boolean,
    default: true
  }
}, {
  timestamps: true
});

module.exports = mongoose.model('TestAssignment', testAssignmentSchema);