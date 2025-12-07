const mongoose = require('mongoose');

const codingQuestionSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true,
    trim: true
  },
  description: {
    type: String,
    required: true
  },
  difficulty: {
    type: String,
    required: true,
    enum: ['easy', 'medium', 'hard']
  },
  constraints: {
    type: String,
    default: ''
  },
  input_format: {
    type: String,
    default: ''
  },
  output_format: {
    type: String,
    default: ''
  },
  time_limit: {
    type: Number,
    default: 2000
  },
  memory_limit: {
    type: Number,
    default: 256
  },
  supported_languages: {
    type: [String],
    default: ['javascript', 'python', 'java', 'cpp']
  },
  sample_input: {
    type: String,
    default: ''
  },
  sample_output: {
    type: String,
    default: ''
  },
  explanation: {
    type: String,
    default: ''
  },
  tags: {
    type: [String],
    default: []
  },
  created_by: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }
}, {
  timestamps: {
    createdAt: 'created_at',
    updatedAt: 'updated_at'
  }
});

codingQuestionSchema.index({ difficulty: 1 });
codingQuestionSchema.index({ created_by: 1 });
codingQuestionSchema.index({ tags: 1 });

module.exports = mongoose.model('CodingQuestion', codingQuestionSchema);
