const express = require('express');
const Test = require('../models/Test');
const TestAttempt = require('../models/TestAttempt');
const TestAssignment = require('../models/TestAssignment');
const User = require('../models/User');
const College = require('../models/College');
const { auth, authorize } = require('../middleware/auth');
const logger = require('../middleware/logger');

const router = express.Router();

// Master Admin - Overall reports
router.get('/master/overview', auth, authorize('master_admin'), async (req, res) => {
  try {
    const totalTests = await Test.countDocuments({ isActive: true });
    const totalAttempts = await TestAttempt.countDocuments({ isActive: true });
    const totalAssignments = await TestAssignment.countDocuments({ isActive: true });
    
    // Subject-wise statistics
    const subjectStats = await Test.aggregate([
      { $match: { isActive: true } },
      {
        $group: {
          _id: '$subject',
          testCount: { $sum: 1 },
          totalQuestions: { $sum: '$numberOfQuestions' }
        }
      }
    ]);

    // Performance by subject
    const subjectPerformance = await TestAttempt.aggregate([
      {
        $lookup: {
          from: 'tests',
          localField: 'testId',
          foreignField: '_id',
          as: 'test'
        }
      },
      { $unwind: '$test' },
      {
        $group: {
          _id: '$test.subject',
          averagePercentage: { $avg: '$percentage' },
          totalAttempts: { $sum: 1 },
          averageMarks: { $avg: '$marksObtained' }
        }
      }
    ]);

    // College-wise performance
    const collegePerformance = await TestAttempt.aggregate([
      {
        $lookup: {
          from: 'colleges',
          localField: 'collegeId',
          foreignField: '_id',
          as: 'college'
        }
      },
      { $unwind: '$college' },
      {
        $group: {
          _id: '$collegeId',
          collegeName: { $first: '$college.name' },
          averagePercentage: { $avg: '$percentage' },
          totalAttempts: { $sum: 1 },
          studentsParticipated: { $addToSet: '$studentId' }
        }
      },
      {
        $addFields: {
          studentsCount: { $size: '$studentsParticipated' }
        }
      },
      { $sort: { averagePercentage: -1 } }
    ]);

    // Recent test attempts
    const recentAttempts = await TestAttempt.find({ isActive: true })
      .populate('testId', 'testName subject')
      .populate('studentId', 'name email')
      .populate('collegeId', 'name')
      .sort({ createdAt: -1 })
      .limit(10);

    res.json({
      overview: {
        totalTests,
        totalAttempts,
        totalAssignments
      },
      subjectStats,
      subjectPerformance,
      collegePerformance,
      recentAttempts
    });

  } catch (error) {
    logger.errorLog(error, { context: 'Master admin reports error' });
    res.status(500).json({ error: 'Server error' });
  }
});

// Master Admin - Detailed test report
router.get('/master/test/:testId', auth, authorize('master_admin'), async (req, res) => {
  try {
    const testId = req.params.testId;
    
    const test = await Test.findById(testId);
    if (!test) {
      return res.status(404).json({ error: 'Test not found' });
    }

    const attempts = await TestAttempt.find({ testId, isActive: true })
      .populate('studentId', 'name email branch batch section')
      .populate('collegeId', 'name')
      .sort({ percentage: -1 });

    // Calculate statistics
    const totalAttempts = attempts.length;
    const averagePercentage = attempts.reduce((sum, attempt) => sum + attempt.percentage, 0) / totalAttempts || 0;
    const highestScore = attempts.length > 0 ? attempts[0].percentage : 0;
    const lowestScore = attempts.length > 0 ? attempts[attempts.length - 1].percentage : 0;

    // Question-wise analysis
    const questionAnalysis = test.questions.map(question => {
      const questionAttempts = attempts.map(attempt => 
        attempt.answers.find(answer => answer.questionId.toString() === question._id.toString())
      ).filter(Boolean);

      const correctCount = questionAttempts.filter(answer => answer.isCorrect).length;
      const totalCount = questionAttempts.length;
      const accuracy = totalCount > 0 ? (correctCount / totalCount) * 100 : 0;

      // Option distribution
      const optionDistribution = { A: 0, B: 0, C: 0, D: 0 };
      questionAttempts.forEach(answer => {
        if (answer.selectedAnswer) {
          optionDistribution[answer.selectedAnswer]++;
        }
      });

      return {
        questionId: question._id,
        questionText: question.questionText,
        correctAnswer: question.correctAnswer,
        accuracy,
        correctCount,
        totalCount,
        optionDistribution
      };
    });

    res.json({
      test,
      statistics: {
        totalAttempts,
        averagePercentage,
        highestScore,
        lowestScore
      },
      attempts,
      questionAnalysis
    });

  } catch (error) {
    logger.errorLog(error, { context: 'Test report error' });
    res.status(500).json({ error: 'Server error' });
  }
});

// College Admin - College reports
router.get('/college/overview', auth, authorize('college_admin'), async (req, res) => {
  try {
    const collegeId = req.user.collegeId;

    const totalAttempts = await TestAttempt.countDocuments({ 
      collegeId, 
      isActive: true 
    });

    const assignedTests = await TestAssignment.countDocuments({
      collegeId,
      assignedTo: 'students',
      status: 'accepted',
      isActive: true
    });

    // Subject-wise performance for college
    const subjectPerformance = await TestAttempt.aggregate([
      { $match: { collegeId, isActive: true } },
      {
        $lookup: {
          from: 'tests',
          localField: 'testId',
          foreignField: '_id',
          as: 'test'
        }
      },
      { $unwind: '$test' },
      {
        $group: {
          _id: '$test.subject',
          averagePercentage: { $avg: '$percentage' },
          totalAttempts: { $sum: 1 },
          averageMarks: { $avg: '$marksObtained' }
        }
      }
    ]);

    // Branch-wise performance
    const branchPerformance = await TestAttempt.aggregate([
      { $match: { collegeId, isActive: true } },
      {
        $lookup: {
          from: 'users',
          localField: 'studentId',
          foreignField: '_id',
          as: 'student'
        }
      },
      { $unwind: '$student' },
      {
        $group: {
          _id: '$student.branch',
          averagePercentage: { $avg: '$percentage' },
          totalAttempts: { $sum: 1 },
          studentsCount: { $addToSet: '$studentId' }
        }
      },
      {
        $addFields: {
          studentsParticipated: { $size: '$studentsCount' }
        }
      },
      { $sort: { averagePercentage: -1 } }
    ]);

    // Top performers
    const topPerformers = await TestAttempt.find({ 
      collegeId, 
      isActive: true 
    })
    .populate('studentId', 'name email branch batch section')
    .populate('testId', 'testName subject')
    .sort({ percentage: -1 })
    .limit(10);

    res.json({
      overview: {
        totalAttempts,
        assignedTests
      },
      subjectPerformance,
      branchPerformance,
      topPerformers
    });

  } catch (error) {
    logger.errorLog(error, { context: 'College reports error' });
    res.status(500).json({ error: 'Server error' });
  }
});

// Faculty - Branch/Section reports
router.get('/faculty/overview', auth, authorize('faculty'), async (req, res) => {
  try {
    const facultyBranch = req.user.branch;
    const collegeId = req.user.collegeId;

    // Get students in faculty's branch
    const branchStudents = await User.find({
      collegeId,
      role: 'student',
      branch: facultyBranch,
      isActive: true
    }).select('_id');

    const studentIds = branchStudents.map(student => student._id);

    const totalAttempts = await TestAttempt.countDocuments({
      studentId: { $in: studentIds },
      isActive: true
    });

    // Subject-wise performance for branch students
    const subjectPerformance = await TestAttempt.aggregate([
      { $match: { studentId: { $in: studentIds }, isActive: true } },
      {
        $lookup: {
          from: 'tests',
          localField: 'testId',
          foreignField: '_id',
          as: 'test'
        }
      },
      { $unwind: '$test' },
      {
        $group: {
          _id: '$test.subject',
          averagePercentage: { $avg: '$percentage' },
          totalAttempts: { $sum: 1 }
        }
      }
    ]);

    // Student performance in branch
    const studentPerformance = await TestAttempt.aggregate([
      { $match: { studentId: { $in: studentIds }, isActive: true } },
      {
        $lookup: {
          from: 'users',
          localField: 'studentId',
          foreignField: '_id',
          as: 'student'
        }
      },
      { $unwind: '$student' },
      {
        $group: {
          _id: '$studentId',
          studentName: { $first: '$student.name' },
          studentEmail: { $first: '$student.email' },
          batch: { $first: '$student.batch' },
          section: { $first: '$student.section' },
          averagePercentage: { $avg: '$percentage' },
          totalAttempts: { $sum: 1 },
          totalMarks: { $sum: '$marksObtained' }
        }
      },
      { $sort: { averagePercentage: -1 } }
    ]);

    res.json({
      overview: {
        totalAttempts,
        branchStudents: studentIds.length
      },
      subjectPerformance,
      studentPerformance
    });

  } catch (error) {
    logger.errorLog(error, { context: 'Faculty reports error' });
    res.status(500).json({ error: 'Server error' });
  }
});

// Student - Personal performance report
router.get('/student/performance', auth, authorize('student'), async (req, res) => {
  try {
    const studentId = req.user._id;

    const attempts = await TestAttempt.find({ 
      studentId, 
      isActive: true 
    })
    .populate('testId', 'testName subject totalMarks startDateTime')
    .sort({ createdAt: -1 });

    if (attempts.length === 0) {
      return res.json({
        message: 'No test attempts found',
        attempts: [],
        subjectWisePerformance: [],
        overallStats: {
          totalAttempts: 0,
          averagePercentage: 0,
          totalMarksObtained: 0,
          totalPossibleMarks: 0
        }
      });
    }

    // Subject-wise performance
    const subjectWisePerformance = {};
    attempts.forEach(attempt => {
      const subject = attempt.testId.subject;
      if (!subjectWisePerformance[subject]) {
        subjectWisePerformance[subject] = {
          subject,
          attempts: 0,
          totalMarks: 0,
          marksObtained: 0,
          averagePercentage: 0
        };
      }
      
      subjectWisePerformance[subject].attempts++;
      subjectWisePerformance[subject].totalMarks += attempt.totalMarks;
      subjectWisePerformance[subject].marksObtained += attempt.marksObtained;
    });

    // Calculate averages
    Object.values(subjectWisePerformance).forEach(subject => {
      subject.averagePercentage = (subject.marksObtained / subject.totalMarks) * 100;
    });

    // Overall statistics
    const totalAttempts = attempts.length;
    const totalMarksObtained = attempts.reduce((sum, attempt) => sum + attempt.marksObtained, 0);
    const totalPossibleMarks = attempts.reduce((sum, attempt) => sum + attempt.totalMarks, 0);
    const averagePercentage = (totalMarksObtained / totalPossibleMarks) * 100;

    res.json({
      attempts,
      subjectWisePerformance: Object.values(subjectWisePerformance),
      overallStats: {
        totalAttempts,
        averagePercentage,
        totalMarksObtained,
        totalPossibleMarks
      }
    });

  } catch (error) {
    logger.errorLog(error, { context: 'Student performance error' });
    res.status(500).json({ error: 'Server error' });
  }
});

// College Admin - Hierarchical reports
router.get('/college/hierarchical', auth, authorize('college_admin'), async (req, res) => {
  try {
    const { batch, branch, section } = req.query;
    const collegeId = req.user.collegeId;

    // Build filter query
    let studentFilter = { collegeId, role: 'student', isActive: true };
    if (batch && batch !== 'all') studentFilter.batch = batch;
    if (branch && branch !== 'all') studentFilter.branch = branch;
    if (section && section !== 'all') studentFilter.section = section;

    // Get students matching filter
    const students = await User.find(studentFilter).select('_id name email branch batch section');
    const studentIds = students.map(s => s._id);

    if (studentIds.length === 0) {
      return res.json({
        students: [],
        performance: [],
        summary: {
          totalStudents: 0,
          totalAttempts: 0,
          averagePercentage: 0
        }
      });
    }

    // Get test attempts for these students
    const attempts = await TestAttempt.find({
      studentId: { $in: studentIds },
      isActive: true
    })
    .populate('testId', 'testName subject testType')
    .populate('studentId', 'name email branch batch section')
    .sort({ createdAt: -1 });

    // Calculate student performance
    const studentPerformance = {};
    attempts.forEach(attempt => {
      const studentId = attempt.studentId._id.toString();
      if (!studentPerformance[studentId]) {
        studentPerformance[studentId] = {
          student: attempt.studentId,
          attempts: [],
          totalAttempts: 0,
          averagePercentage: 0,
          totalMarks: 0,
          marksObtained: 0
        };
      }
      
      studentPerformance[studentId].attempts.push(attempt);
      studentPerformance[studentId].totalAttempts++;
      studentPerformance[studentId].totalMarks += attempt.totalMarks;
      studentPerformance[studentId].marksObtained += attempt.marksObtained;
    });

    // Calculate averages
    Object.values(studentPerformance).forEach(perf => {
      perf.averagePercentage = perf.totalMarks > 0 ? (perf.marksObtained / perf.totalMarks) * 100 : 0;
    });

    // Summary statistics
    const totalAttempts = attempts.length;
    const averagePercentage = attempts.length > 0 
      ? attempts.reduce((sum, attempt) => sum + attempt.percentage, 0) / attempts.length 
      : 0;

    res.json({
      students,
      performance: Object.values(studentPerformance),
      attempts,
      summary: {
        totalStudents: students.length,
        totalAttempts,
        averagePercentage
      }
    });

  } catch (error) {
    logger.errorLog(error, { context: 'Hierarchical reports error' });
    res.status(500).json({ error: 'Server error' });
  }
});

// Faculty - Branch/Section hierarchical reports
router.get('/faculty/hierarchical', auth, authorize('faculty'), async (req, res) => {
  try {
    const { batch, section } = req.query;
    const facultyBranch = req.user.branch;
    const collegeId = req.user.collegeId;

    // Build filter for students in faculty's branch
    let studentFilter = {
      collegeId,
      role: 'student',
      branch: facultyBranch,
      isActive: true
    };

    if (batch && batch !== 'all') studentFilter.batch = batch;
    if (section && section !== 'all') studentFilter.section = section;

    const students = await User.find(studentFilter).select('_id name email branch batch section');
    const studentIds = students.map(s => s._id);

    if (studentIds.length === 0) {
      return res.json({
        students: [],
        performance: [],
        sectionPerformance: [],
        attempts: [],
        summary: {
          totalStudents: 0,
          totalAttempts: 0,
          averagePercentage: 0
        }
      });
    }

    const attempts = await TestAttempt.find({
      studentId: { $in: studentIds },
      isActive: true
    })
    .populate('testId', 'testName subject testType')
    .populate('studentId', 'name email branch batch section')
    .sort({ createdAt: -1 });

    // Calculate student performance
    const studentPerformance = {};
    attempts.forEach(attempt => {
      const studentId = attempt.studentId._id.toString();
      if (!studentPerformance[studentId]) {
        studentPerformance[studentId] = {
          student: attempt.studentId,
          attempts: [],
          totalAttempts: 0,
          averagePercentage: 0,
          totalMarks: 0,
          marksObtained: 0
        };
      }

      studentPerformance[studentId].attempts.push(attempt);
      studentPerformance[studentId].totalAttempts++;
      studentPerformance[studentId].totalMarks += attempt.totalMarks;
      studentPerformance[studentId].marksObtained += attempt.marksObtained;
    });

    // Calculate student averages
    Object.values(studentPerformance).forEach(perf => {
      perf.averagePercentage = perf.totalMarks > 0 ? (perf.marksObtained / perf.totalMarks) * 100 : 0;
    });

    // Group by section for faculty view
    const sectionPerformance = {};
    attempts.forEach(attempt => {
      const section = attempt.studentId.section;
      if (!sectionPerformance[section]) {
        sectionPerformance[section] = {
          section,
          attempts: [],
          students: new Set(),
          totalAttempts: 0,
          totalMarks: 0,
          marksObtained: 0,
          averagePercentage: 0
        };
      }

      sectionPerformance[section].attempts.push(attempt);
      sectionPerformance[section].students.add(attempt.studentId._id.toString());
      sectionPerformance[section].totalAttempts++;
      sectionPerformance[section].totalMarks += attempt.totalMarks;
      sectionPerformance[section].marksObtained += attempt.marksObtained;
    });

    // Calculate section averages
    Object.values(sectionPerformance).forEach(section => {
      section.averagePercentage = section.totalMarks > 0 ? (section.marksObtained / section.totalMarks) * 100 : 0;
      section.studentsCount = section.students.size;
    });

    res.json({
      students,
      performance: Object.values(studentPerformance),
      sectionPerformance: Object.values(sectionPerformance),
      attempts,
      summary: {
        totalStudents: students.length,
        totalAttempts: attempts.length,
        averagePercentage: attempts.length > 0
          ? attempts.reduce((sum, attempt) => sum + attempt.percentage, 0) / attempts.length
          : 0
      }
    });

  } catch (error) {
    logger.errorLog(error, { context: 'Faculty hierarchical reports error' });
    res.status(500).json({ error: 'Server error' });
  }
});

// Utility: Remove orphaned TestAttempt documents (no valid test)
const removeOrphanedAttempts = async () => {
  const attempts = await TestAttempt.find({});
  for (const attempt of attempts) {
    const test = await Test.findById(attempt.testId);
    if (!test || !test.isActive) {
      await TestAttempt.deleteOne({ _id: attempt._id });
    }
  }
};

// Optionally call this utility on server start or via an admin endpoint
// removeOrphanedAttempts();

module.exports = router;