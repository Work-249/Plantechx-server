const mongoose = require('mongoose');

const testCodingSectionSchema = new mongoose.Schema({
  test_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Test',
    required: true
  },
  question_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'CodingQuestion',
    required: true
  },
  points: {
    type: Number,
    default: 100
  },
  order_index: {
    type: Number,
    default: 0
  }
}, {
  timestamps: {
    createdAt: 'created_at',
    updatedAt: false
  }
});

testCodingSectionSchema.index({ test_id: 1 });
testCodingSectionSchema.index({ question_id: 1 });
testCodingSectionSchema.index({ test_id: 1, question_id: 1 }, { unique: true });

module.exports = mongoose.model('TestCodingSection', testCodingSectionSchema);
