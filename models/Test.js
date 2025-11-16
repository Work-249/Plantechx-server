const mongoose = require('mongoose');

const questionSchema = new mongoose.Schema({
  questionText: {
    type: String,
    required: true,
    trim: true
  },
  questionImageUrl: {
    type: String,
    trim: true,
    default: null
  },
  options: {
    A: { type: String, required: true, trim: true },
    B: { type: String, required: true, trim: true },
    C: { type: String, required: true, trim: true },
    D: { type: String, required: true, trim: true }
  },
  optionImages: {
    A: { type: String, trim: true, default: null },
    B: { type: String, trim: true, default: null },
    C: { type: String, trim: true, default: null },
    D: { type: String, trim: true, default: null }
  },
  correctAnswer: {
    type: String,
    required: true,
    enum: ['A', 'B', 'C', 'D']
  },
  marks: {
    type: Number,
    required: true,
    min: 1
  }
}, { _id: true });

const sectionSchema = new mongoose.Schema({
  sectionName: {
    type: String,
    required: true,
    trim: true
  },
  sectionDuration: {
    type: Number,
    required: true,
    min: 1
  },
  numberOfQuestions: {
    type: Number,
    required: true,
    min: 1
  },
  marksPerQuestion: {
    type: Number,
    required: true,
    min: 1
  },
  questions: [questionSchema]
}, { _id: true });

const testSchema = new mongoose.Schema({
  testName: {
    type: String,
    required: true,
    trim: true
  },
  testDescription: {
    type: String,
    required: true,
    trim: true
  },
  subject: {
    type: String,
    required: false,
    enum: ['Verbal', 'Reasoning', 'Technical', 'Arithmetic', 'Communication'],
    default: null
  },
  testType: {
    type: String,
    enum: ['Assessment', 'Practice', 'Assignment', 'Mock Test', 'Specific Company Test'],
    default: 'Assessment'
  },
  companyName: {
    type: String,
    trim: true,
    default: null
  },
  topics: [{
    type: String,
    trim: true
  }],
  difficulty: {
    type: String,
    enum: ['Easy', 'Medium', 'Hard'],
    default: 'Medium'
  },
  numberOfQuestions: {
    type: Number,
    required: false,
    min: 0,
    default: 0
  },
  marksPerQuestion: {
    type: Number,
    required: false,
    min: 0,
    default: 0
  },
  totalMarks: {
    type: Number
  },
  duration: {
    type: Number, // in minutes
    required: false,
    min: 0,
    default: 0
  },
  startDateTime: {
    type: Date,
    required: true
  },
  endDateTime: {
    type: Date,
    required: true
  },
  questions: [questionSchema],
  hasSections: {
    type: Boolean,
    default: false
  },
  sections: [sectionSchema],
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  sourceType: {
    type: String,
    enum: ['manual', 'pdf', 'json', 'csv'],
    default: 'manual'
  },
  originalFileName: {
    type: String
  },
  instructions: [{
    type: String,
    trim: true
  }],
  isActive: {
    type: Boolean,
    default: true
  },
  hasCodingSection: {
    type: Boolean,
    default: false
  },
  codingQuestions: [{
    questionId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'CodingQuestion',
      required: true
    },
    points: {
      type: Number,
      default: 100
    },
    timeLimit: {
      type: Number,
      default: 3600
    }
  }]
}, {
  timestamps: true
});

// Validate based on test type and structure
testSchema.pre('save', function(next) {
  // For coding section validation
  if (this.hasCodingSection && (!this.codingQuestions || this.codingQuestions.length === 0)) {
    return next(new Error('At least one coding question is required when coding section is enabled'));
  }

  // For coding-only tests, MCQ questions are optional
  if (this.hasCodingSection && !this.hasSections) {
    this.numberOfQuestions = this.questions ? this.questions.length : 0;
    this.marksPerQuestion = this.questions && this.questions.length > 0 ? (this.marksPerQuestion || 1) : 0;
    this.duration = this.duration || 60; // Default duration of 60 minutes for coding tests
  }

  // For sectioned tests
  if (this.hasSections && this.sections && this.sections.length > 0) {
    // Validate each section
    let totalQuestionsInSections = 0;
    let totalDuration = 0;
    let calculatedTotalMarks = 0;

    for (const section of this.sections) {
      if (section.questions.length !== section.numberOfQuestions) {
        return next(new Error(`Section "${section.sectionName}" has ${section.questions.length} questions but expects ${section.numberOfQuestions}`));
      }
      totalQuestionsInSections += section.numberOfQuestions;
      totalDuration += section.sectionDuration;
      calculatedTotalMarks += section.numberOfQuestions * section.marksPerQuestion;
    }

    // Update test-level fields based on sections
    this.numberOfQuestions = totalQuestionsInSections;
    this.duration = totalDuration;
    this.totalMarks = calculatedTotalMarks;

    // If test has coding questions, mark hasCodingSection as true
    if (this.codingQuestions && this.codingQuestions.length > 0) {
      this.hasCodingSection = true;
    }
  } else {
    // For non-sectioned tests
    if (this.hasCodingSection) {
      // For coding-only tests, MCQ questions are optional
      this.numberOfQuestions = this.questions.length || 0;
      this.marksPerQuestion = this.questions.length ? (this.marksPerQuestion || 1) : 0;
      this.duration = this.duration || 0;
    } else {
      // For regular MCQ tests, validate required fields
      if (!this.numberOfQuestions || this.numberOfQuestions < 1) {
        return next(new Error('Number of questions must be at least 1 for non-sectioned tests'));
      }
      if (!this.marksPerQuestion || this.marksPerQuestion < 1) {
        return next(new Error('Marks per question must be at least 1 for non-sectioned tests'));
      }
      if (!this.duration || this.duration < 1) {
        return next(new Error('Duration must be at least 1 minute for non-sectioned tests'));
      }

      if (this.questions.length !== this.numberOfQuestions) {
        return next(new Error(`Number of questions (${this.questions.length}) must match the specified count (${this.numberOfQuestions})`));
      }
    }

    // Calculate total marks including coding questions
    let mcqMarks = this.numberOfQuestions * this.marksPerQuestion;
    let codingMarks = 0;

    if (this.codingQuestions && this.codingQuestions.length > 0) {
      codingMarks = this.codingQuestions.reduce((sum, cq) => sum + (cq.points || 100), 0);
      this.hasCodingSection = true;
    }

    this.totalMarks = mcqMarks + codingMarks;
  }

  // Validate start and end dates
  if (this.startDateTime >= this.endDateTime) {
    return next(new Error('End date must be after start date'));
  }

  next();
});

module.exports = mongoose.model('Test', testSchema);