const mongoose = require('mongoose');

const answerSchema = new mongoose.Schema({
  questionId: {
    type: mongoose.Schema.Types.ObjectId,
    required: true
  },
  selectedAnswer: {
    type: String,
    enum: ['A', 'B', 'C', 'D'],
    required: true
  },
  isCorrect: {
    type: Boolean,
    required: true
  },
  marksObtained: {
    type: Number,
    required: true,
    min: 0
  },
  timeSpent: {
    type: Number, // in seconds
    default: 0
  }
}, { _id: false });

const testAttemptSchema = new mongoose.Schema({
  testId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Test',
    required: true
  },
  studentId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  collegeId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'College',
    required: true
  },
  startTime: {
    type: Date,
    required: true
  },
  endTime: {
    type: Date,
    required: true
  },
  timeSpent: {
    type: Number, // in minutes
    required: true
  },
  answers: [answerSchema],
  totalMarks: {
    type: Number,
    required: true
  },
  marksObtained: {
  type: Number,
  default: 0,
  min: 0
},
percentage: {
  type: Number,
  default: 0,
  min: 0,
  max: 100
},
correctAnswers: {
  type: Number,
  default: 0,
  min: 0
},
incorrectAnswers: {
  type: Number,
  default: 0,
  min: 0
},
unanswered: {
  type: Number,
  default: 0,
  min: 0
},
  violations: {
    type: Number,
    default: 0,
    min: 0
  },
  status: {
    type: String,
    enum: ['completed', 'timeout', 'submitted', 'auto-submitted-violations'],
    default: 'completed'
  },
  isActive: {
    type: Boolean,
    default: true
  }
}, {
  timestamps: true
});

// Calculate results before saving
testAttemptSchema.pre('save', function(next) {
  this.correctAnswers = this.answers.filter(answer => answer.isCorrect).length;
  this.incorrectAnswers = this.answers.filter(answer => !answer.isCorrect).length;
  this.unanswered = 0; // All questions must be answered in this implementation
  this.marksObtained = this.answers.reduce((total, answer) => total + answer.marksObtained, 0);
  this.percentage = (this.marksObtained / this.totalMarks) * 100;
  
  next();
});

module.exports = mongoose.model('TestAttempt', testAttemptSchema);
