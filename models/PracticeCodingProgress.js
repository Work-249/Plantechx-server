const mongoose = require('mongoose');

const practiceCodingProgressSchema = new mongoose.Schema({
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
  status: {
    type: String,
    enum: ['attempted', 'solved', 'bookmarked'],
    default: 'attempted'
  },
  best_score: {
    type: Number,
    default: 0
  },
  attempts: {
    type: Number,
    default: 0
  },
  last_attempted_at: {
    type: Date,
    default: Date.now
  },
  solved_at: {
    type: Date,
    default: null
  }
}, {
  timestamps: false
});

practiceCodingProgressSchema.index({ student_id: 1 });
practiceCodingProgressSchema.index({ question_id: 1 });
practiceCodingProgressSchema.index({ student_id: 1, question_id: 1 }, { unique: true });
practiceCodingProgressSchema.index({ status: 1 });

module.exports = mongoose.model('PracticeCodingProgress', practiceCodingProgressSchema);
