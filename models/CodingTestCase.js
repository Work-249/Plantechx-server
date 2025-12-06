const mongoose = require('mongoose');

const codingTestCaseSchema = new mongoose.Schema({
  question_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'CodingQuestion',
    required: true
  },
  input: {
    type: String,
    required: true
  },
  expected_output: {
    type: String,
    required: true
  },
  is_sample: {
    type: Boolean,
    default: false
  },
  weight: {
    type: Number,
    default: 10
  }
}, {
  timestamps: {
    createdAt: 'created_at',
    updatedAt: false
  }
});

codingTestCaseSchema.index({ question_id: 1 });
codingTestCaseSchema.index({ is_sample: 1 });

module.exports = mongoose.model('CodingTestCase', codingTestCaseSchema);
