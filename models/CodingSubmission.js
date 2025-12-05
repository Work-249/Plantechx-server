const mongoose = require('mongoose');

const codingSubmissionSchema = new mongoose.Schema({
  student_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  question_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'CodingQuestion',
    required: true
  },
  test_attempt_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'TestAttempt',
    default: null
  },
  language: {
    type: String,
    required: true
  },
  code: {
    type: String,
    required: true
  },
  status: {
    type: String,
    required: true,
    enum: ['pending', 'running', 'accepted', 'wrong_answer', 'runtime_error', 'time_limit_exceeded', 'memory_limit_exceeded', 'compilation_error'],
    default: 'pending'
  },
  test_cases_passed: {
    type: Number,
    default: 0
  },
  total_test_cases: {
    type: Number,
    default: 0
  },
  score: {
    type: Number,
    default: 0
  },
  execution_time: {
    type: Number,
    default: 0
  },
  memory_used: {
    type: Number,
    default: 0
  },
  test_results: {
    type: mongoose.Schema.Types.Mixed,
    default: []
  },
  error_message: {
    type: String,
    default: null
  }
}, {
  timestamps: {
    createdAt: 'submitted_at',
    updatedAt: false
  }
});

codingSubmissionSchema.index({ student_id: 1 });
codingSubmissionSchema.index({ question_id: 1 });
codingSubmissionSchema.index({ test_attempt_id: 1 });
codingSubmissionSchema.index({ student_id: 1, question_id: 1 });

module.exports = mongoose.model('CodingSubmission', codingSubmissionSchema);
