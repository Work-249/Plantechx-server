const express = require('express');
const multer = require('multer');
const path = require('path');
const Test = require('../models/Test');
const TestAssignment = require('../models/TestAssignment');
const TestAttempt = require('../models/TestAttempt');
const College = require('../models/College');
const User = require('../models/User');
const CodingQuestion = require('../models/CodingQuestion');
const { auth, authorize } = require('../middleware/auth');
const emailService = require('../utils/emailService');
const PDFExtractor = require('../utils/pdfExtractor');
const FileExtractor = require('../utils/fileExtractor');
const { body, validationResult } = require('express-validator');
const logger = require('../middleware/logger');

const router = express.Router();

// Configure multer for file uploads (memory storage)
const upload = multer({
  storage: multer.memoryStorage(),
  fileFilter: (req, file, cb) => {
    if (file.mimetype === 'application/pdf') {
      cb(null, true);
    } else {
      cb(new Error('Only PDF files are allowed'), false);
    }
  },
  limits: {
    fileSize: 10 * 1024 * 1024 // 10MB limit
  }
});

const fileUpload = multer({
  storage: multer.memoryStorage(),
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['application/json', 'text/csv', 'application/vnd.ms-excel'];
    if (allowedTypes.includes(file.mimetype) || file.originalname.endsWith('.csv')) {
      cb(null, true);
    } else {
      cb(new Error('Only JSON and CSV files are allowed'), false);
    }
  },
  limits: {
    fileSize: 5 * 1024 * 1024 // 5MB limit
  }
});

// Create test (Master Admin only)
router.post('/', auth, authorize('master_admin'), [
  // Add debug logging for request body
  (req, res, next) => {
    console.log('Full request body:', JSON.stringify(req.body, null, 2));
    next();
  },
  body('testName').trim().isLength({ min: 3 }).withMessage('Test name must be at least 3 characters'),
  body('testDescription').trim().isLength({ min: 10 }).withMessage('Test description must be at least 10 characters'),
  body('subject').optional().isIn(['Verbal', 'Reasoning', 'Technical', 'Arithmetic', 'Communication']).withMessage('Invalid subject'),
  body('testType').optional().isIn(['Assessment', 'Practice', 'Mock Test', 'Specific Company Test']).withMessage('Invalid test type'),
  body('topics').optional().isArray().withMessage('Topics must be an array'),
  body('difficulty').optional().isIn(['Easy', 'Medium', 'Hard']).withMessage('Invalid difficulty'),
  body('hasSections').optional().isBoolean().withMessage('hasSections must be a boolean'),
  body('sections').optional().isArray().withMessage('Sections must be an array'),
  body('numberOfQuestions').optional().custom((value, { req }) => {
    if (req.body.hasSections === true || req.body.hasSections === 'true') return true;
    if (req.body.hasCodingSection === true || req.body.hasCodingSection === 'true') {
      // For coding tests, numberOfQuestions can be 0
      if (value === undefined || value === null || value < 0 || value > 100) {
        throw new Error('Number of questions must be between 0 and 100 for coding tests');
      }
    } else {
      // For regular MCQ tests
      if (value === undefined || value === null || value < 1 || value > 100) {
        throw new Error('Number of questions must be between 1 and 100');
      }
    }
    return true;
  }),
  body('marksPerQuestion').optional().custom((value, { req }) => {
    if (req.body.hasSections === true || req.body.hasSections === 'true') return true;
    if (req.body.hasCodingSection === true || req.body.hasCodingSection === 'true') return true;
    if (value === undefined || value === null || value < 1 || value > 10) {
      throw new Error('Marks per question must be between 1 and 10');
    }
    return true;
  }),
  body('duration').optional().custom((value, { req }) => {
    if (req.body.hasSections === true || req.body.hasSections === 'true') return true;
    if (req.body.hasCodingSection === true || req.body.hasCodingSection === 'true') return true;
    if (value === undefined || value === null || value < 5 || value > 300) {
      throw new Error('Duration must be between 5 and 300 minutes');
    }
    return true;
  }),
  body('startDateTime').isISO8601().withMessage('Invalid start date format'),
  body('endDateTime').isISO8601().withMessage('Invalid end date format'),
  body('questions').optional().isArray().withMessage('Questions must be an array')
], async (req, res) => {
  try {
    console.log('Received test creation request');
    console.log('Request body keys:', Object.keys(req.body));
    console.log('Test name:', req.body.testName);
    console.log('Questions count:', req.body.questions?.length);
    console.log('Has coding section:', req.body.hasCodingSection);
    console.log('Coding questions:', req.body.codingQuestions);
    console.log('Validation result:', validationResult(req));

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      console.log('Validation errors:', JSON.stringify(errors.array(), null, 2));
      return res.status(400).json({
        error: 'Validation failed',
        errors: errors.array()
      });
    }

    let {
      testName,
      testDescription,
      subject,
      testType = 'Assessment',
      companyName,
      topics = [],
      difficulty = 'Medium',
      hasSections = false,
      sections = [],
      numberOfQuestions,
      marksPerQuestion,
      duration,
      startDateTime,
      endDateTime,
      questions,
      hasCodingSection = false,
      codingQuestions = []
    } = req.body;

    // Normalize codingQuestions: accept { id } or { questionId } from frontend
    const normalizedCodingQuestions = (codingQuestions || []).map(cq => ({
      questionId: cq.questionId || cq.id || cq._id,
      points: typeof cq.points !== 'undefined' ? cq.points : (cq.points || 100),
      timeLimit: typeof cq.timeLimit !== 'undefined' ? cq.timeLimit : (cq.time_limit || cq.timeLimit || 3600)
    }));

    // Validate companyName for Specific Company Test
    if (testType === 'Specific Company Test' && (!companyName || !companyName.trim())) {
      return res.status(400).json({
        error: 'Company name is required for Specific Company tests'
      });
    }

    // Validate coding section if enabled
    if (hasCodingSection) {
      if (!normalizedCodingQuestions || normalizedCodingQuestions.length === 0) {
        return res.status(400).json({
          error: 'At least one coding question is required when coding section is enabled'
        });
      }

      // Validate coding question points and timeLimit
      for (const cq of normalizedCodingQuestions) {
        if (typeof cq.points !== 'undefined' && (cq.points < 0 || cq.points > 1000)) {
          return res.status(400).json({
            error: 'Coding question points must be between 0 and 1000'
          });
        }
        if (typeof cq.timeLimit !== 'undefined' && (cq.timeLimit < 0 || cq.timeLimit > 7200)) {
          return res.status(400).json({
            error: 'Coding question time limit must be between 0 and 7200 seconds'
          });
        }
      }

      // Validate coding question IDs exist
      for (const cq of normalizedCodingQuestions) {
        if (!cq.questionId) {
          return res.status(400).json({
            error: 'Each coding question must have a questionId or id'
          });
        }

        const exists = await CodingQuestion.findById(cq.questionId);
        if (!exists) {
          return res.status(400).json({
            error: `Coding question with ID ${cq.questionId} not found`
          });
        }
      }
    }

    // Validate based on test structure
    if (hasSections) {
      // Validate sections
      if (!sections || sections.length === 0) {
        return res.status(400).json({
          error: 'At least one section is required when sections are enabled'
        });
      }

      // Validate each section and its questions
      for (let i = 0; i < sections.length; i++) {
        const section = sections[i];

        if (!section.sectionName || !section.sectionName.trim()) {
          return res.status(400).json({
            error: `Section ${i + 1} must have a name`
          });
        }

        if (!section.questions || section.questions.length !== section.numberOfQuestions) {
          return res.status(400).json({
            error: `Section "${section.sectionName}" has ${section.questions?.length || 0} questions but expects ${section.numberOfQuestions}`
          });
        }

        // Validate each question in the section
        for (let j = 0; j < section.questions.length; j++) {
          const question = section.questions[j];
          if (!question.questionText || !question.options || !question.correctAnswer) {
            return res.status(400).json({
              error: `Question ${j + 1} in section "${section.sectionName}" is incomplete`
            });
          }

          if (!question.options.A || !question.options.B || !question.options.C || !question.options.D) {
            return res.status(400).json({
              error: `Question ${j + 1} in section "${section.sectionName}" must have all four options`
            });
          }

          if (!['A', 'B', 'C', 'D'].includes(question.correctAnswer)) {
            return res.status(400).json({
              error: `Question ${j + 1} in section "${section.sectionName}" must have a valid correct answer`
            });
          }

          // Ensure marks are set
          question.marks = section.marksPerQuestion;
        }
      }
    } else {
      // Validate non-sectioned test questions
      if (!hasCodingSection) {
        // Only validate question count for non-coding tests
        if (!questions || questions.length !== numberOfQuestions) {
          console.log('Question count mismatch:', questions?.length, 'vs', numberOfQuestions);
          return res.status(400).json({
            error: `Number of questions (${questions?.length || 0}) must match the specified count (${numberOfQuestions})`
          });
        }
      } else {
        // For coding tests, questions are optional
        numberOfQuestions = questions?.length || 0;
      }

      // Validate each question
      for (let i = 0; i < questions.length; i++) {
        const question = questions[i];
        if (!question.questionText || !question.options || !question.correctAnswer) {
          console.log('Question validation failed at index:', i, question);
          return res.status(400).json({
            error: `Question ${i + 1} is incomplete`
          });
        }

        if (!question.options.A || !question.options.B || !question.options.C || !question.options.D) {
          console.log('Question options validation failed at index:', i, question.options);
          return res.status(400).json({
            error: `Question ${i + 1} must have all four options (A, B, C, D)`
          });
        }

        if (!['A', 'B', 'C', 'D'].includes(question.correctAnswer)) {
          console.log('Correct answer validation failed at index:', i, question.correctAnswer);
          return res.status(400).json({
            error: `Question ${i + 1} must have a valid correct answer (A, B, C, or D)`
          });
        }

        // Add marks to each question
        question.marks = marksPerQuestion;
      }
    }

    console.log('Creating test with validated data');
    console.log('Start DateTime received:', startDateTime);
    console.log('End DateTime received:', endDateTime);

    const test = new Test({
      testName,
      testDescription,
      subject,
      testType,
      companyName: companyName || null,
      topics,
      difficulty,
      hasSections,
      sections: hasSections ? sections : [],
      numberOfQuestions: hasSections ? 0 : numberOfQuestions,
      marksPerQuestion: hasSections ? 0 : marksPerQuestion,
      duration: hasSections ? 0 : duration,
      startDateTime: new Date(startDateTime),
      endDateTime: new Date(endDateTime),
      questions: hasSections ? [] : questions,
      hasCodingSection,
      codingQuestions: hasCodingSection ? normalizedCodingQuestions.map(cq => ({
        questionId: cq.questionId,
        points: cq.points || 100,
        timeLimit: cq.timeLimit || 3600
      })) : [],
      createdBy: req.user._id,
      collegeId: req.user.collegeId
    });

    await test.save();
    console.log('Test created successfully:', test._id);

    res.status(201).json({
      message: 'Test created successfully',
      test: {
        id: test._id,
        testName: test.testName,
        testType: test.testType,
        companyName: test.companyName,
        subject: test.subject,
        topics: test.topics,
        difficulty: test.difficulty,
        numberOfQuestions: test.numberOfQuestions,
        totalMarks: test.totalMarks,
        duration: test.duration,
        startDateTime: test.startDateTime,
        endDateTime: test.endDateTime,
        createdAt: test.createdAt
      }
    });

  } catch (error) {
    logger.errorLog(error, { context: 'Create test error' });
    res.status(500).json({ error: 'Server error' });
  }
});

// Extract questions from PDF
router.post('/extract-pdf', auth, authorize('master_admin'), upload.single('pdf'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'PDF file is required' });
    }

    console.log('Processing PDF file:', req.file.originalname, 'Size:', req.file.size);

    const questions = await PDFExtractor.extractMCQs(req.file.buffer);
    
    if (questions.length === 0) {
      return res.status(400).json({ 
        error: 'No valid MCQ questions found in the PDF. Please ensure your PDF contains:\n• Numbered questions (1., 2., etc.)\n• Options labeled A), B), C), D)\n• Clear answer indicators (Answer: A, Correct: B, etc.)' 
      });
    }

    console.log('Successfully extracted questions:', questions.length);

    res.json({
      message: `Successfully extracted ${questions.length} questions`,
      questions: questions.map(q => ({
        ...q,
        marks: 1 // Default marks, can be changed later
      }))
    });

  } catch (error) {
    logger.errorLog(error, { context: 'PDF extraction error' });
    res.status(500).json({ 
      error: error.message || 'Failed to process PDF. Please ensure the PDF is not corrupted and contains readable text.' 
    });
  }
});

// Generate sample questions
router.get('/sample-questions/:subject', auth, authorize('master_admin'), async (req, res) => {
  try {
    const { subject } = req.params;
    const count = parseInt(req.query.count) || 5;

    const questions = PDFExtractor.generateSampleQuestions(count, subject);

    res.json({
      message: `Generated ${questions.length} sample questions for ${subject}`,
      questions: questions.map(q => ({
        ...q,
        marks: 1
      }))
    });

  } catch (error) {
    logger.errorLog(error, { context: 'Sample questions error' });
    res.status(500).json({ error: 'Server error' });
  }
});

// Extract questions from JSON/CSV file
router.post('/extract-file', auth, authorize('master_admin'), fileUpload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'File is required' });
    }

    const fileExtension = path.extname(req.file.originalname).toLowerCase();

    let questions = [];

    if (fileExtension === '.json') {
      questions = await FileExtractor.extractFromJSON(req.file.buffer);
    } else if (fileExtension === '.csv') {
      questions = await FileExtractor.extractFromCSV(req.file.buffer);
    } else {
      return res.status(400).json({ error: 'Unsupported file type' });
    }

    res.json({
      message: `Successfully extracted ${questions.length} questions from ${fileExtension.toUpperCase()} file`,
      questions: questions.map(q => ({
        ...q,
        marks: 1
      }))
    });

  } catch (error) {
    logger.errorLog(error, { context: 'File extraction error' });
    res.status(500).json({
      error: error.message || 'Failed to extract questions from file',
      details: error.toString()
    });
  }
});

// Get all tests (Master Admin only)
router.get('/', auth, authorize('master_admin'), async (req, res) => {
  try {
    const { testType, subject } = req.query;
    
    let query = { isActive: true };
    
    if (testType && testType !== 'all') {
      query.testType = testType;
    }
    
    if (subject && subject !== 'all') {
      query.subject = subject;
    }
    
    const tests = await Test.find(query)
      .populate('createdBy', 'name email')
      .populate('codingQuestions.questionId')
      .sort({ createdAt: -1 });

    // Get attempt counts for all tests
    const attemptCounts = await TestAttempt.aggregate([
      {
        $match: {
          isActive: true
        }
      },
      {
        $group: {
          _id: '$testId',
          count: { $sum: 1 }
        }
      }
    ]);

    // Create a map of testId -> attemptCount
    const attemptCountMap = new Map();
    attemptCounts.forEach(ac => {
      attemptCountMap.set(ac._id.toString(), ac.count);
    });

    // Add attemptCount to each test
    const testsWithAttempts = tests.map(test => {
      const testObj = test.toObject();
      testObj.attemptCount = attemptCountMap.get(test._id.toString()) || 0;
      return testObj;
    });

    res.json(testsWithAttempts);
  } catch (error) {
    logger.errorLog(error, { context: 'Get tests error' });
    res.status(500).json({ error: 'Server error' });
  }
});

// Get test by ID with questions (Master Admin only)
router.get('/:id', auth, authorize('master_admin'), async (req, res) => {
  try {
    const test = await Test.findById(req.params.id)
      .populate('createdBy', 'name email')
      .populate('codingQuestions.questionId');

    if (!test) {
      return res.status(404).json({ error: 'Test not found' });
    }

    res.json(test);
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Assign test to college (Master Admin only)
router.post('/:id/assign-college', auth, authorize('master_admin'), [
  body('collegeIds').isArray({ min: 1 })
], async (req, res) => {
  try {
    const { collegeIds } = req.body;
    const testId = req.params.id;

    const test = await Test.findById(testId);
    if (!test) {
      return res.status(404).json({ error: 'Test not found' });
    }

    const colleges = await College.find({ _id: { $in: collegeIds }, isActive: true });
    if (colleges.length !== collegeIds.length) {
      return res.status(400).json({ error: 'Some colleges not found or inactive' });
    }

    const assignments = [];
    for (const college of colleges) {
      // Check if already assigned
      const existingAssignment = await TestAssignment.findOne({
        testId,
        collegeId: college._id,
        isActive: true
      });

      if (!existingAssignment) {
        const assignment = new TestAssignment({
          testId,
          collegeId: college._id,
          assignedBy: req.user._id,
          assignedTo: 'college'
        });

        await assignment.save();
        assignments.push(assignment);

        // Send email notification
        const collegeAdmin = await User.findById(college.adminId);
        if (collegeAdmin) {
          await emailService.sendTestAssignmentNotification(
            collegeAdmin.email,
            collegeAdmin.name,
            test.testName,
            college.name,
            test.startDateTime,
            test.endDateTime
          );
        }
      }
    }

    res.json({
      message: `Test assigned to ${assignments.length} colleges successfully`,
      assignments: assignments.length
    });

  } catch (error) {
    logger.errorLog(error, { context: 'Assign test error' });
    res.status(500).json({ error: 'Server error' });
  }
});

// Get colleges assigned to a specific test (Master Admin)
router.get('/:id/assigned-colleges', auth, authorize('master_admin'), async (req, res) => {
  try {
    const testId = req.params.id;

    const assignments = await TestAssignment.find({
      testId: testId,
      assignedTo: 'college',
      isActive: true
    })
    .populate('collegeId', 'name code email')
    .select('collegeId status assignedAt');

    res.json(assignments);
  } catch (error) {
    logger.errorLog(error, { context: 'Get test assigned colleges error' });
    res.status(500).json({ error: 'Server error' });
  }
});

// Get all tests with assignment status for college (College Admin and Faculty)
router.get('/college/all-tests', auth, authorize('college_admin', 'faculty'), async (req, res) => {
  try {
    const { testType, subject } = req.query;

    let query = { isActive: true };
    if (testType && testType !== 'all') {
      query.testType = testType;
    }
    if (subject && subject !== 'all') {
      query.subject = subject;
    }

    // Get only active tests
    const allTests = await Test.find(query).sort({ createdAt: -1 });
    const activeTestIds = new Set(allTests.map(t => t._id.toString()));

    // Get assignments - but filter to only include tests that still exist
    const assignments = await TestAssignment.find({
      collegeId: req.user.collegeId,
      assignedTo: 'college',
      isActive: true,
      testId: { $in: Array.from(activeTestIds) }  // Only get assignments for active tests
    }).select('testId status assignedAt assignedBy').populate('assignedBy', 'name email');

    // Get student assignments - but filter to only include tests that still exist
    const studentAssignments = await TestAssignment.find({
      collegeId: req.user.collegeId,
      assignedTo: 'students',
      isActive: true,
      testId: { $in: Array.from(activeTestIds) }  // Only get assignments for active tests
    }).select('testId studentFilters');

    // Get attempt counts - only for active tests
    const TestAttempt = require('../models/TestAttempt');
    const attemptCounts = await TestAttempt.aggregate([
      {
        $match: {
          collegeId: req.user.collegeId,
          isActive: true,
          testId: { $in: Array.from(activeTestIds) }  // Only count attempts for active tests
        }
      },
      {
        $group: {
          _id: '$testId',
          count: { $sum: 1 }
        }
      }
    ]);

    const assignmentMap = new Map();
    assignments.forEach(assignment => {
      if (assignment.testId) {
        assignmentMap.set(assignment.testId.toString(), {
          status: assignment.status,
          assignedAt: assignment.assignedAt,
          assignedBy: assignment.assignedBy,
          assignmentId: assignment._id
        });
      }
    });

    // Build student assignment info map
    const studentAssignmentMap = new Map();
    for (const sa of studentAssignments) {
      const testIdStr = sa.testId.toString();
      if (!studentAssignmentMap.has(testIdStr)) {
        studentAssignmentMap.set(testIdStr, {
          studentIds: new Set(),
          branches: new Set(),
          batches: new Set()
        });
      }

      const data = studentAssignmentMap.get(testIdStr);
      if (sa.studentFilters && sa.studentFilters.specificStudents) {
        sa.studentFilters.specificStudents.forEach(sid => {
          data.studentIds.add(sid.toString());
        });
      }
    }

    // Get student details for branches and batches
    for (const [testId, data] of studentAssignmentMap.entries()) {
      if (data.studentIds.size > 0) {
        const students = await User.find({
          _id: { $in: Array.from(data.studentIds) }
        }).select('branch batch');

        students.forEach(student => {
          if (student.branch) data.branches.add(student.branch);
          if (student.batch) data.batches.add(student.batch);
        });
      }
    }

    // Build attempt count map
    const attemptCountMap = new Map();
    attemptCounts.forEach(ac => {
      attemptCountMap.set(ac._id.toString(), ac.count);
    });

    const testsWithStatus = allTests.map(test => {
      const assignment = assignmentMap.get(test._id.toString());
      const studentInfo = studentAssignmentMap.get(test._id.toString());
      const attemptCount = attemptCountMap.get(test._id.toString()) || 0;

      return {
        ...test.toObject(),
        assignmentStatus: assignment ? assignment.status : 'not_assigned',
        assignedAt: assignment ? assignment.assignedAt : null,
        assignedBy: assignment ? assignment.assignedBy : null,
        assignmentId: assignment ? assignment.assignmentId : null,
        assignedStudentCount: studentInfo ? studentInfo.studentIds.size : 0,
        attemptCount: attemptCount,
        testBranches: studentInfo ? Array.from(studentInfo.branches) : [],
        testBatches: studentInfo ? Array.from(studentInfo.batches) : []
      };
    });

    res.json(testsWithStatus);
  } catch (error) {
    logger.errorLog(error, { context: 'Get all tests for college error' });
    res.status(500).json({ error: 'Server error' });
  }
});

// Get assigned tests for college (College Admin and Faculty)
router.get('/college/assigned', auth, authorize('college_admin', 'faculty'), async (req, res) => {
  try {
    const { testType, subject } = req.query;

    // Get assignments and tests in parallel
    const [assignments, tests] = await Promise.all([
      TestAssignment.find({
        collegeId: req.user.collegeId,
        assignedTo: 'college',
        isActive: true
      })
      .populate('testId')
      .populate('assignedBy', 'name email')
      .sort({ createdAt: -1 }),
      Test.find({ isActive: true }, '_id') // Only get active tests for validation
    ]);

    // Create a Set of valid test IDs
    const validTestIds = new Set(tests.map(t => t._id.toString()));

    // Filter out assignments where testId is null or test no longer exists or is inactive
    let filteredAssignments = assignments.filter(assignment => 
      assignment.testId && validTestIds.has(assignment.testId._id.toString())
    );

    if (testType && testType !== 'all') {
      filteredAssignments = filteredAssignments.filter(assignment =>
        assignment.testId && assignment.testId.testType === testType
      );
    }

    if (subject && subject !== 'all') {
      filteredAssignments = filteredAssignments.filter(assignment =>
        assignment.testId && assignment.testId.subject === subject
      );
    }

    res.json(filteredAssignments);
  } catch (error) {
    logger.errorLog(error, { context: 'Get assigned tests error' });
    res.status(500).json({ error: 'Server error' });
  }
});

// Accept/Reject test assignment (College Admin)
router.put('/assignment/:id/status', auth, authorize('college_admin'), [
  body('status').isIn(['accepted', 'rejected'])
], async (req, res) => {
  try {
    const { status } = req.body;
    const assignment = await TestAssignment.findOne({
      _id: req.params.id,
      collegeId: req.user.collegeId
    });

    if (!assignment) {
      return res.status(404).json({ error: 'Assignment not found' });
    }

    assignment.status = status;
    if (status === 'accepted') {
      assignment.acceptedAt = new Date();
    } else {
      assignment.rejectedAt = new Date();
    }

    await assignment.save();

    res.json({
      message: `Test assignment ${status} successfully`,
      assignment
    });

  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Assign test to students (College Admin)
router.post('/assignment/:id/assign-students', auth, authorize('college_admin'), [
  body('branches').optional().isArray(),
  body('batches').optional().isArray(),
  body('sections').optional().isArray(),
  body('specificStudents').optional().isArray()
], async (req, res) => {
  try {
    const { branches, batches, sections, specificStudents } = req.body;
    const assignmentId = req.params.id;

    const assignment = await TestAssignment.findOne({
      _id: assignmentId,
      collegeId: req.user.collegeId,
      status: 'accepted'
    }).populate('testId');

    if (!assignment) {
      return res.status(404).json({ error: 'Assignment not found or not accepted' });
    }

    // Build student query
    let studentQuery = {
      collegeId: req.user.collegeId,
      role: 'student',
      isActive: true
    };

    if (branches && branches.length > 0) {
      studentQuery.branch = { $in: branches };
    }
    if (batches && batches.length > 0) {
      studentQuery.batch = { $in: batches };
    }
    if (sections && sections.length > 0) {
      studentQuery.section = { $in: sections };
    }
    if (specificStudents && specificStudents.length > 0) {
      studentQuery._id = { $in: specificStudents };
    }

    const students = await User.find(studentQuery);

    if (students.length === 0) {
      return res.status(400).json({ error: 'No students found matching the criteria' });
    }

    // Create student assignments
    const studentAssignments = [];
    for (const student of students) {
      const studentAssignment = new TestAssignment({
        testId: assignment.testId._id,
        collegeId: req.user.collegeId,
        assignedBy: req.user._id,
        assignedTo: 'students',
        studentFilters: {
          specificStudents: [student._id]
        },
        status: 'accepted' // Students don't need to accept
      });

      await studentAssignment.save();
      studentAssignments.push(studentAssignment);

      // Send email notification to student
      await emailService.sendTestAssignmentToStudent(
        student.email,
        student.name,
        assignment.testId.testName,
        assignment.testId.startDateTime,
        assignment.testId.endDateTime,
        assignment.testId.duration
      );
    }

    res.json({
      message: `Test assigned to ${students.length} students successfully`,
      studentsAssigned: students.length
    });

  } catch (error) {
    logger.errorLog(error, { context: 'Assign to students error' });
    res.status(500).json({ error: 'Server error' });
  }
});

// Get assigned tests for student
router.get('/student/assigned', auth, authorize('student'), async (req, res) => {
  try {
    const { testType, subject } = req.query;
    
    // Get assignments, tests, and attempts in parallel
    const [assignments, tests] = await Promise.all([
      TestAssignment.find({
        'studentFilters.specificStudents': req.user._id,
        assignedTo: 'students',
        status: 'accepted',
        isActive: true
      })
      .populate({
        path: 'testId',
        populate: {
          path: 'codingQuestions.questionId'
        }
      })
      .sort({ createdAt: -1 }),
      Test.find({ isActive: true }, '_id') // Only get active tests for validation
    ]);

    // Create a Set of valid test IDs
    const validTestIds = new Set(tests.map(t => t._id.toString()));

    // Filter out assignments where testId is null, test no longer exists, or test is inactive
    const validAssignments = assignments.filter(assignment => 
      assignment.testId && validTestIds.has(assignment.testId._id.toString())
    );

    // Check if student has already attempted each test
    const testsWithAttempts = await Promise.all(
      validAssignments.map(async (assignment) => {
        const attempt = await TestAttempt.findOne({
          testId: assignment.testId._id,
          studentId: req.user._id
        });

        return {
          ...assignment.toObject(),
          hasAttempted: !!attempt,
          attempt: attempt
        };
      })
    );

    // Filter by test type and subject if provided
    let filteredTests = testsWithAttempts;
    
    if (testType && testType !== 'all') {
      filteredTests = filteredTests.filter(test => 
        test.testId.testType === testType
      );
    }
    
    if (subject && subject !== 'all') {
      filteredTests = filteredTests.filter(test => 
        test.testId.subject === subject
      );
    }
    res.json(filteredTests);
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Start test (Student)
router.post('/:id/start', auth, authorize('student'), async (req, res) => {
  try {
    const testId = req.params.id;
    
    // Check if test is assigned to student
    const assignment = await TestAssignment.findOne({
      testId,
      'studentFilters.specificStudents': req.user._id,
      status: 'accepted',
      isActive: true
    });

    if (!assignment) {
      return res.status(403).json({ error: 'Test not assigned to you' });
    }

    // Check if already attempted
    const existingAttempt = await TestAttempt.findOne({
      testId,
      studentId: req.user._id
    });

    if (existingAttempt) {
      return res.status(400).json({ error: 'Test already attempted' });
    }

    const test = await Test.findById(testId).populate('codingQuestions.questionId');
    if (!test) {
      return res.status(404).json({ error: 'Test not found' });
    }

    // Check if test is currently active
    const now = new Date();
    if (now < test.startDateTime) {
      return res.status(400).json({ error: 'Test has not started yet' });
    }
    if (now > test.endDateTime) {
      return res.status(400).json({ error: 'Test has ended' });
    }

    // Return test questions (include correctAnswer for Practice tests only)
    const testForStudent = {
      _id: test._id,
      testName: test.testName,
      testDescription: test.testDescription,
      subject: test.subject,
      testType: test.testType,
      hasSections: test.hasSections,
      numberOfQuestions: test.numberOfQuestions,
      marksPerQuestion: test.marksPerQuestion,
      totalMarks: test.totalMarks,
      duration: test.duration,
      startDateTime: test.startDateTime,
      endDateTime: test.endDateTime,
      hasCodingSection: test.hasCodingSection
    };

    // Handle sectioned tests
    if (test.hasSections && test.sections && test.sections.length > 0) {
      testForStudent.sections = test.sections.map(section => ({
        _id: section._id,
        sectionName: section.sectionName,
        sectionDuration: section.sectionDuration,
        numberOfQuestions: section.numberOfQuestions,
        marksPerQuestion: section.marksPerQuestion,
        questions: section.questions.map(q => {
          const questionData = {
            _id: q._id,
            questionText: q.questionText,
            options: q.options,
            marks: q.marks,
            // include optional image fields so students can see images
            questionImageUrl: q.questionImageUrl || undefined,
            optionImages: q.optionImages || undefined
          };

          // Include correct answer for Practice tests
          if (test.testType === 'Practice') {
            questionData.correctAnswer = q.correctAnswer;
          }

          return questionData;
        })
      }));
    } else {
      // Handle non-sectioned tests
      testForStudent.questions = test.questions.map(q => {
        const questionData = {
          _id: q._id,
          questionText: q.questionText,
          options: q.options,
          marks: q.marks,
          // expose optional image fields for student UI
          questionImageUrl: q.questionImageUrl || undefined,
          optionImages: q.optionImages || undefined
        };

        // Include correct answer for Practice tests
        if (test.testType === 'Practice') {
          questionData.correctAnswer = q.correctAnswer;
        }

        return questionData;
      });
    }

    // Add coding questions if enabled
    if (test.hasCodingSection && test.codingQuestions && test.codingQuestions.length > 0) {
      testForStudent.codingQuestions = test.codingQuestions.map(cq => ({
        _id: cq.questionId._id,
        title: cq.questionId.title,
        description: cq.questionId.description,
        difficulty: cq.questionId.difficulty,
        constraints: cq.questionId.constraints,
        input_format: cq.questionId.input_format,
        output_format: cq.questionId.output_format,
        time_limit: cq.questionId.time_limit,
        memory_limit: cq.questionId.memory_limit,
        supported_languages: cq.questionId.supported_languages,
        sample_input: cq.questionId.sample_input,
        sample_output: cq.questionId.sample_output,
        explanation: cq.questionId.explanation,
        tags: cq.questionId.tags,
        points: cq.points,
        timeLimit: cq.timeLimit
      }));
    }

    res.json({
      message: 'Test started successfully',
      test: testForStudent,
      startTime: now
    });

  } catch (error) {
    logger.errorLog(error, { context: 'Start test error' });
    res.status(500).json({ error: 'Server error' });
  }
});

// Submit test (Student)
router.post('/:id/submit', auth, authorize('student'), [
  body('answers').isArray({ min: 1 }),
  body('startTime').isISO8601(),
  body('timeSpent').isInt({ min: 0 }),
  body('violations').optional().isInt({ min: 0 })
], async (req, res) => {
  try {
    const { answers, startTime, timeSpent, violations = 0 } = req.body;
    const testId = req.params.id;

    // Verify test assignment
    const assignment = await TestAssignment.findOne({
      testId,
      'studentFilters.specificStudents': req.user._id,
      status: 'accepted',
      isActive: true
    });

    if (!assignment) {
      return res.status(403).json({ error: 'Test not assigned to you' });
    }

    // Check if already attempted
    const existingAttempt = await TestAttempt.findOne({
      testId,
      studentId: req.user._id
    });

    if (existingAttempt) {
      return res.status(400).json({ error: 'Test already submitted' });
    }

    const test = await Test.findById(testId);
    if (!test) {
      return res.status(404).json({ error: 'Test not found' });
    }

    // Get all questions from test (handle both sectioned and non-sectioned)
    let allQuestions = [];
    if (test.hasSections && test.sections && test.sections.length > 0) {
      test.sections.forEach(section => {
        allQuestions = allQuestions.concat(section.questions);
      });
    } else {
      allQuestions = test.questions;
    }

    // Calculate results
    const processedAnswers = [];
    for (let i = 0; i < answers.length; i++) {
      const answer = answers[i];
      const question = allQuestions.find(q => q._id.toString() === answer.questionId);

      if (!question) {
        return res.status(400).json({ error: `Invalid question ID: ${answer.questionId}` });
      }

      const isCorrect = question.correctAnswer === answer.selectedAnswer;
      const marksObtained = isCorrect ? question.marks : 0;

      processedAnswers.push({
        questionId: question._id,
        selectedAnswer: answer.selectedAnswer,
        isCorrect,
        marksObtained,
        timeSpent: answer.timeSpent || 0
      });
    }

    // Determine status based on violations
    let status = 'completed';
    if (violations >= 3) {
      status = 'auto-submitted-violations';
    }

    // Create test attempt
    const testAttempt = new TestAttempt({
      testId,
      studentId: req.user._id,
      collegeId: req.user.collegeId,
      startTime: new Date(startTime),
      endTime: new Date(),
      timeSpent,
      answers: processedAnswers,
      totalMarks: test.totalMarks,
      violations,
      status
    });

    await testAttempt.save();

    // Return results based on test type
    const responseData = {
      message: 'Test submitted successfully',
      testType: test.testType,
      results: {
        totalMarks: testAttempt.totalMarks,
        marksObtained: testAttempt.marksObtained,
        percentage: testAttempt.percentage,
        correctAnswers: testAttempt.correctAnswers,
        incorrectAnswers: testAttempt.incorrectAnswers,
        timeSpent: testAttempt.timeSpent,
        submittedAt: testAttempt.createdAt
      }
    };

    // For Practice tests, include immediate feedback
    if (test.testType === 'Practice') {
      responseData.instantFeedback = processedAnswers.map((answer, index) => ({
        questionId: answer.questionId,
        question: test.questions[index],
        selectedAnswer: answer.selectedAnswer,
        correctAnswer: test.questions[index].correctAnswer,
        isCorrect: answer.isCorrect,
        explanation: `The correct answer is ${test.questions[index].correctAnswer}: ${test.questions[index].options[test.questions[index].correctAnswer]}`
      }));
    }

    res.json(responseData);

  } catch (error) {
    logger.errorLog(error, { context: 'Submit test error' });
    res.status(500).json({ error: 'Server error' });
  }
});

// Get test results for student
router.get('/:id/results', auth, authorize('student'), async (req, res) => {
  try {
    const testId = req.params.id;
    
    const attempt = await TestAttempt.findOne({
      testId,
      studentId: req.user._id
    }).populate('testId', 'testName subject totalMarks questions');

    if (!attempt) {
      return res.status(404).json({ error: 'Test attempt not found' });
    }

    // Include correct answers for review
    const detailedResults = {
      ...attempt.toObject(),
      questionAnalysis: attempt.testId.questions.map(question => {
        const studentAnswer = attempt.answers.find(a => 
          a.questionId.toString() === question._id.toString()
        );
        
        return {
          questionText: question.questionText,
          options: question.options,
          correctAnswer: question.correctAnswer,
          studentAnswer: studentAnswer?.selectedAnswer,
          isCorrect: studentAnswer?.isCorrect,
          marksObtained: studentAnswer?.marksObtained,
          marks: question.marks
        };
      })
    };

    res.json(detailedResults);
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Update test (Master Admin only)
router.put('/:id', auth, authorize('master_admin'), [
  body('testName').trim().isLength({ min: 3 }),
  body('testDescription').trim().isLength({ min: 10 }),
  body('subject').optional().isIn(['Verbal', 'Reasoning', 'Technical', 'Arithmetic', 'Communication']),
  body('testType').optional().isIn(['Assessment', 'Practice', 'Assignment', 'Mock Test', 'Specific Company Test']),
  body('hasSections').optional().isBoolean().withMessage('hasSections must be a boolean'),
  body('sections').optional().isArray().withMessage('Sections must be an array'),
  body('numberOfQuestions').optional().custom((value, { req }) => {
    if (req.body.hasSections === true || req.body.hasSections === 'true') return true;
    if (value === undefined || value === null || value < 1 || value > 100) {
      throw new Error('Number of questions must be between 1 and 100');
    }
    return true;
  }),
  body('marksPerQuestion').optional().custom((value, { req }) => {
    if (req.body.hasSections === true || req.body.hasSections === 'true') return true;
    if (req.body.hasCodingSection === true || req.body.hasCodingSection === 'true') return true;
    if (value === undefined || value === null || value < 1 || value > 10) {
      throw new Error('Marks per question must be between 1 and 10');
    }
    return true;
  }),
  body('duration').optional().custom((value, { req }) => {
    if (req.body.hasSections === true || req.body.hasSections === 'true') return true;
    if (req.body.hasCodingSection === true || req.body.hasCodingSection === 'true') return true;
    if (value === undefined || value === null || value < 5 || value > 300) {
      throw new Error('Duration must be between 5 and 300 minutes');
    }
    return true;
  }),
  body('startDateTime').isISO8601(),
  body('endDateTime').isISO8601(),
  body('questions').optional().isArray()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const testId = req.params.id;
    const updateData = req.body;

    // Validate based on test structure
    if (updateData.hasSections) {
      // Validate sections
      if (!updateData.sections || updateData.sections.length === 0) {
        return res.status(400).json({
          error: 'At least one section is required when sections are enabled'
        });
      }

      // Validate each section
      for (let i = 0; i < updateData.sections.length; i++) {
        const section = updateData.sections[i];

        if (!section.questions || section.questions.length !== section.numberOfQuestions) {
          return res.status(400).json({
            error: `Section "${section.sectionName}" has ${section.questions?.length || 0} questions but expects ${section.numberOfQuestions}`
          });
        }

        // Set marks for each question in section
        section.questions.forEach(question => {
          question.marks = section.marksPerQuestion;
        });
      }
    } else {
      // Validate non-sectioned test questions
      if (!updateData.questions || updateData.questions.length !== updateData.numberOfQuestions) {
        return res.status(400).json({
          error: `Number of questions (${updateData.questions?.length || 0}) must match the specified count (${updateData.numberOfQuestions})`
        });
      }

      // Add marks to each question
      updateData.questions.forEach(question => {
        question.marks = updateData.marksPerQuestion;
      });
    }

    const test = await Test.findByIdAndUpdate(
      testId,
      updateData,
      { new: true, runValidators: true }
    );

    if (!test) {
      return res.status(404).json({ error: 'Test not found' });
    }

    res.json({
      message: 'Test updated successfully',
      test
    });

  } catch (error) {
    logger.errorLog(error, { context: 'Update test error' });
    res.status(500).json({ error: 'Server error' });
  }
});

// Delete test (Master Admin only)
router.delete('/:id', auth, authorize('master_admin'), async (req, res) => {
  try {
    const testId = req.params.id;
    
    // Soft delete the test by marking isActive as false
    const test = await Test.findByIdAndUpdate(
      testId,
      { isActive: false },
      { new: true }
    );
    
    if (!test) {
      return res.status(404).json({ error: 'Test not found' });
    }
    
    // Soft delete all related assignments and attempts
    await Promise.all([
      TestAssignment.updateMany(
        { testId },
        { $set: { isActive: false } }
      ),
      TestAttempt.updateMany(
        { testId },
        { $set: { isActive: false } }
      ),
      // Also soft delete all related reports (if reports are stored in TestAttempt or a separate collection)
      // If reports are a separate collection, add:
      // Report.updateMany({ testId }, { $set: { isActive: false } })
    ]);

    res.json({ message: 'Test deleted successfully' });

  } catch (error) {
    logger.errorLog(error, { context: 'Delete test error' });
    res.status(500).json({ error: 'Server error' });
  }
});

// Get student test reports (Student)
router.get('/student/reports', auth, authorize('student'), async (req, res) => {
  try {
    const { testType, subject } = req.query;

    let query = {
      studentId: req.user._id,
      status: 'completed'
    };

    const attempts = await TestAttempt.find(query)
      .populate({
        path: 'testId',
        select: 'testName testType subject totalMarks difficulty companyName questions'
      })
      .sort({ createdAt: -1 });

    let filteredAttempts = attempts;

    if (testType && testType !== 'all') {
      filteredAttempts = filteredAttempts.filter(attempt =>
        attempt.testId && attempt.testId.testType === testType
      );
    }

    if (subject && subject !== 'all') {
      filteredAttempts = filteredAttempts.filter(attempt =>
        attempt.testId && attempt.testId.subject === subject
      );
    }

    const reports = filteredAttempts.map(attempt => ({
      _id: attempt._id,
      testId: {
        testName: attempt.testId?.testName || 'Unknown Test',
        testType: attempt.testId?.testType || 'Unknown',
        subject: attempt.testId?.subject || 'Unknown',
        companyName: attempt.testId?.companyName,
        difficulty: attempt.testId?.difficulty,
        totalMarks: attempt.totalMarks,
        questions: attempt.testId?.questions || []
      },
      studentId: {
        name: req.user.name,
        email: req.user.email,
        batch: req.user.batch,
        branch: req.user.branch,
        section: req.user.section
      },
      testName: attempt.testId?.testName || 'Unknown Test',
      testType: attempt.testId?.testType || 'Unknown',
      subject: attempt.testId?.subject || 'Unknown',
      companyName: attempt.testId?.companyName,
      difficulty: attempt.testId?.difficulty,
      totalMarks: attempt.totalMarks,
      marksObtained: attempt.marksObtained,
      percentage: attempt.percentage,
      correctAnswers: attempt.correctAnswers,
      incorrectAnswers: attempt.incorrectAnswers,
      timeSpent: attempt.timeSpent,
      status: attempt.percentage >= 40 ? 'Pass' : 'Fail',
      completedAt: attempt.createdAt,
      startTime: attempt.startTime,
      endTime: attempt.endTime,
      createdAt: attempt.createdAt,
      questionAnalysis: attempt.testId?.questions?.map((question, index) => {
        const studentAnswer = attempt.answers.find(a =>
          a.questionId.toString() === question._id.toString()
        );

        return {
          questionText: question.questionText,
          options: question.options,
          correctAnswer: question.correctAnswer,
          studentAnswer: studentAnswer?.selectedAnswer || 'Not answered',
          isCorrect: studentAnswer?.isCorrect || false,
          marksObtained: studentAnswer?.marksObtained || 0,
          marks: question.marks
        };
      }) || []
    }));

    res.json(reports);
  } catch (error) {
    logger.errorLog(error, { context: 'Get student reports error' });
    res.status(500).json({ error: 'Server error' });
  }
});

// Get all students test reports (Faculty and College Admin)
router.get('/faculty/student-reports', auth, authorize('faculty', 'college_admin'), async (req, res) => {
  try {
    const { testType, subject, studentName, batch, branch, section } = req.query;

    let userQuery = {
      collegeId: req.user.collegeId,
      role: 'student',
      isActive: true
    };

    if (batch) userQuery.batch = batch;
    if (branch) userQuery.branch = branch;
    if (section) userQuery.section = section;
    if (studentName) {
      userQuery.name = { $regex: studentName, $options: 'i' };
    }

    const students = await User.find(userQuery).select('_id name email batch branch section');

    if (students.length === 0) {
      return res.json([]);
    }

    const studentIds = students.map(s => s._id);

    const attempts = await TestAttempt.find({
      studentId: { $in: studentIds },
      status: 'completed'
    })
    .populate({
      path: 'testId',
      select: 'testName testType subject totalMarks difficulty companyName'
    })
    .populate({
      path: 'studentId',
      select: 'name email batch branch section'
    })
    .sort({ createdAt: -1 });

    let filteredAttempts = attempts;

    if (testType && testType !== 'all') {
      filteredAttempts = filteredAttempts.filter(attempt =>
        attempt.testId && attempt.testId.testType === testType
      );
    }

    if (subject && subject !== 'all') {
      filteredAttempts = filteredAttempts.filter(attempt =>
        attempt.testId && attempt.testId.subject === subject
      );
    }

    const reports = filteredAttempts.map(attempt => ({
      _id: attempt._id,
      studentName: attempt.studentId?.name || 'Unknown',
      studentEmail: attempt.studentId?.email || 'Unknown',
      batch: attempt.studentId?.batch,
      branch: attempt.studentId?.branch,
      section: attempt.studentId?.section,
      testName: attempt.testId?.testName || 'Unknown Test',
      testType: attempt.testId?.testType || 'Unknown',
      subject: attempt.testId?.subject || 'Unknown',
      companyName: attempt.testId?.companyName,
      difficulty: attempt.testId?.difficulty,
      totalMarks: attempt.totalMarks,
      marksObtained: attempt.marksObtained,
      percentage: attempt.percentage,
      correctAnswers: attempt.correctAnswers,
      incorrectAnswers: attempt.incorrectAnswers,
      timeSpent: attempt.timeSpent,
      status: attempt.percentage >= 40 ? 'Pass' : 'Fail',
      completedAt: attempt.createdAt,
      startTime: attempt.startTime,
      endTime: attempt.endTime
    }));

    res.json(reports);
  } catch (error) {
    logger.errorLog(error, { context: 'Get faculty student reports error' });
    res.status(500).json({ error: 'Server error' });
  }
});

// Configure multer for image uploads
const imageUpload = multer({
  storage: multer.memoryStorage(),
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp'];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Only image files (JPEG, PNG, GIF, WebP) are allowed'), false);
    }
  },
  limits: {
    fileSize: 5 * 1024 * 1024 // 5MB limit
  }
});

// Upload question image
router.post('/upload-image', auth, authorize('master_admin', 'faculty'), imageUpload.single('image'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No image file provided' });
    }

    // Convert image to base64 data URL
    const base64Image = req.file.buffer.toString('base64');
    const mimeType = req.file.mimetype;
    const imageUrl = `data:${mimeType};base64,${base64Image}`;

    res.json({
      success: true,
      imageUrl,
      message: 'Image uploaded successfully'
    });
  } catch (error) {
    logger.errorLog(error, { context: 'Image upload error' });
    res.status(500).json({ error: 'Failed to upload image' });
  }
});

module.exports = router;
