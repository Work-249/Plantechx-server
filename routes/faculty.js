const express = require('express');
const Test = require('../models/Test');
const TestAssignment = require('../models/TestAssignment');
const TestAttempt = require('../models/TestAttempt');
const User = require('../models/User');
const { auth, authorize } = require('../middleware/auth');
const logger = require('../middleware/logger');

const router = express.Router();

router.get('/tests/assigned', auth, authorize('faculty'), async (req, res) => {
  try {
    const { testType, subject } = req.query;

    const query = {
      collegeId: req.user.collegeId,
      assignedTo: 'college',
      status: 'accepted',
      isActive: true
    };

    const assignments = await TestAssignment.find(query)
      .populate('testId')
      .sort({ createdAt: -1 });

    // Filter to only include active tests
    let filteredAssignments = assignments.filter(a => a.testId && a.testId.isActive === true);

    if (testType && testType !== 'all') {
      filteredAssignments = filteredAssignments.filter(
        assignment => assignment.testId.testType === testType
      );
    }

    if (subject && subject !== 'all') {
      filteredAssignments = filteredAssignments.filter(
        assignment => assignment.testId.subject === subject
      );
    }

    const testsWithAnalytics = await Promise.all(
      filteredAssignments.map(async (assignment) => {
        const testId = assignment.testId._id;

        const studentAssignments = await TestAssignment.countDocuments({
          testId,
          collegeId: req.user.collegeId,
          assignedTo: 'students',
          isActive: true
        });

        const attempts = await TestAttempt.find({
          testId,
          collegeId: req.user.collegeId,
          status: 'completed'
        });

        const totalStudents = studentAssignments;
        const completed = attempts.length;
        const avgScore = attempts.length > 0
          ? attempts.reduce((sum, a) => sum + a.percentage, 0) / attempts.length
          : 0;

        return {
          _id: assignment._id,
          testId: assignment.testId,
          assignedDate: assignment.createdAt,
          totalStudents,
          completed,
          completed_count: completed,
          avgScore: avgScore.toFixed(1),
          status: assignment.status,
          attemptCount: completed
        };
      })
    );

    res.json(testsWithAnalytics);
  } catch (error) {
    logger.errorLog(error, { context: 'Get assigned tests error' });
    res.status(500).json({ error: 'Server error' });
  }
});

router.get('/tests/:testId/report', auth, authorize('faculty'), async (req, res) => {
  try {
    const { testId } = req.params;

    const test = await Test.findById(testId);
    if (!test) {
      return res.status(404).json({ error: 'Test not found' });
    }

    const attempts = await TestAttempt.find({
      testId,
      collegeId: req.user.collegeId,
      status: 'completed'
    })
    .populate({
      path: 'studentId',
      select: 'name email batch branch section'
    })
    .sort({ createdAt: -1 });

    const totalStudents = await TestAssignment.countDocuments({
      testId,
      collegeId: req.user.collegeId,
      assignedTo: 'students',
      isActive: true
    });

    const completed = attempts.length;
    const avgScore = attempts.length > 0
      ? attempts.reduce((sum, a) => sum + a.percentage, 0) / attempts.length
      : 0;

    const passedCount = attempts.filter(a => a.percentage >= 40).length;
    const failedCount = completed - passedCount;

    const topStudents = [...attempts]
      .sort((a, b) => b.percentage - a.percentage)
      .slice(0, 5)
      .map(attempt => ({
        name: attempt.studentId?.name || 'Unknown',
        email: attempt.studentId?.email || 'Unknown',
        percentage: attempt.percentage,
        marksObtained: attempt.marksObtained,
        totalMarks: attempt.totalMarks
      }));

    const sectionPerformance = {};
    attempts.forEach(attempt => {
      const section = attempt.studentId?.section || 'Unknown';
      if (!sectionPerformance[section]) {
        sectionPerformance[section] = {
          total: 0,
          sum: 0,
          count: 0
        };
      }
      sectionPerformance[section].sum += attempt.percentage;
      sectionPerformance[section].count += 1;
    });

    const sectionStats = Object.entries(sectionPerformance).map(([section, data]) => ({
      section,
      avgScore: (data.sum / data.count).toFixed(1),
      students: data.count
    }));

    const questionAnalysis = [];
    if (attempts.length > 0) {
      test.questions.forEach((question, index) => {
        const correctCount = attempts.filter(attempt => {
          const answer = attempt.answers.find(
            a => a.questionId.toString() === question._id.toString()
          );
          return answer && answer.isCorrect;
        }).length;

        questionAnalysis.push({
          questionNumber: index + 1,
          questionText: question.questionText.substring(0, 100) + '...',
          correctCount,
          incorrectCount: completed - correctCount,
          correctPercentage: ((correctCount / completed) * 100).toFixed(1)
        });
      });
    }

    res.json({
      test: {
        _id: test._id,
        testName: test.testName,
        testType: test.testType,
        subject: test.subject,
        totalMarks: test.totalMarks,
        numberOfQuestions: test.numberOfQuestions,
        duration: test.duration,
        difficulty: test.difficulty,
        companyName: test.companyName
      },
      analytics: {
        totalStudents,
        completed,
        pending: totalStudents - completed,
        avgScore: avgScore.toFixed(1),
        passedCount,
        failedCount,
        passPercentage: totalStudents > 0 ? ((passedCount / completed) * 100).toFixed(1) : 0
      },
      topStudents,
      sectionStats,
      questionAnalysis,
      attempts: attempts.map(attempt => ({
        _id: attempt._id,
        studentName: attempt.studentId?.name || 'Unknown',
        studentEmail: attempt.studentId?.email || 'Unknown',
        batch: attempt.studentId?.batch,
        branch: attempt.studentId?.branch,
        section: attempt.studentId?.section,
        marksObtained: attempt.marksObtained,
        totalMarks: attempt.totalMarks,
        percentage: attempt.percentage,
        correctAnswers: attempt.correctAnswers,
        incorrectAnswers: attempt.incorrectAnswers,
        timeSpent: attempt.timeSpent,
        completedAt: attempt.createdAt
      }))
    });
  } catch (error) {
    logger.errorLog(error, { context: 'Get test report error' });
    res.status(500).json({ error: 'Server error' });
  }
});

router.get('/tests/:testId/students', auth, authorize('faculty'), async (req, res) => {
  try {
    const { testId } = req.params;

    const test = await Test.findById(testId);
    if (!test) {
      return res.status(404).json({ error: 'Test not found' });
    }

    const attempts = await TestAttempt.find({
      testId,
      collegeId: req.user.collegeId,
      status: 'completed'
    })
    .populate({
      path: 'studentId',
      select: 'name email batch branch section'
    })
    .sort({ percentage: -1 });

    const studentResults = attempts.map(attempt => {
      const questionDetails = attempt.answers.map((answer, index) => {
        const question = test.questions.find(
          q => q._id.toString() === answer.questionId.toString()
        );

        return {
          questionNumber: index + 1,
          questionText: question?.questionText || 'Question not found',
          selectedAnswer: answer.selectedAnswer,
          correctAnswer: question?.correctAnswer,
          isCorrect: answer.isCorrect,
          marksObtained: answer.marksObtained,
          timeSpent: answer.timeSpent
        };
      });

      return {
        _id: attempt._id,
        student: {
          name: attempt.studentId?.name || 'Unknown',
          email: attempt.studentId?.email || 'Unknown',
          batch: attempt.studentId?.batch,
          branch: attempt.studentId?.branch,
          section: attempt.studentId?.section
        },
        marksObtained: attempt.marksObtained,
        totalMarks: attempt.totalMarks,
        percentage: attempt.percentage,
        correctAnswers: attempt.correctAnswers,
        incorrectAnswers: attempt.incorrectAnswers,
        timeSpent: attempt.timeSpent,
        completedAt: attempt.createdAt,
        questionDetails
      };
    });

    res.json({
      testName: test.testName,
      testType: test.testType,
      subject: test.subject,
      totalMarks: test.totalMarks,
      numberOfQuestions: test.numberOfQuestions,
      students: studentResults
    });
  } catch (error) {
    logger.errorLog(error, { context: 'Get test students error' });
    res.status(500).json({ error: 'Server error' });
  }
});

router.get('/tests/:testId/export', auth, authorize('faculty'), async (req, res) => {
  try {
    const { testId } = req.params;
    const { format = 'json' } = req.query;

    const test = await Test.findById(testId);
    if (!test) {
      return res.status(404).json({ error: 'Test not found' });
    }

    const attempts = await TestAttempt.find({
      testId,
      collegeId: req.user.collegeId,
      status: 'completed'
    })
    .populate({
      path: 'studentId',
      select: 'name email batch branch section'
    })
    .sort({ percentage: -1 });

    const exportData = attempts.map(attempt => ({
      'Student Name': attempt.studentId?.name || 'Unknown',
      'Email': attempt.studentId?.email || 'Unknown',
      'Batch': attempt.studentId?.batch || 'N/A',
      'Branch': attempt.studentId?.branch || 'N/A',
      'Section': attempt.studentId?.section || 'N/A',
      'Marks Obtained': attempt.marksObtained,
      'Total Marks': attempt.totalMarks,
      'Percentage': attempt.percentage.toFixed(2) + '%',
      'Correct Answers': attempt.correctAnswers,
      'Incorrect Answers': attempt.incorrectAnswers,
      'Time Spent (min)': attempt.timeSpent,
      'Status': attempt.percentage >= 40 ? 'Pass' : 'Fail',
      'Completed At': new Date(attempt.createdAt).toLocaleString()
    }));

    if (format === 'csv') {
      const headers = Object.keys(exportData[0] || {});
      const csvRows = [
        headers.join(','),
        ...exportData.map(row =>
          headers.map(header => `"${row[header]}"`).join(',')
        )
      ];

      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', `attachment; filename="${test.testName}_results.csv"`);
      res.send(csvRows.join('\n'));
    } else {
      res.json({
        testName: test.testName,
        testType: test.testType,
        subject: test.subject,
        exportedAt: new Date(),
        totalRecords: exportData.length,
        data: exportData
      });
    }
  } catch (error) {
    logger.errorLog(error, { context: 'Export test results error' });
    res.status(500).json({ error: 'Server error' });
  }
});

router.get('/analytics/overview', auth, authorize('faculty'), async (req, res) => {
  try {
    const { timeRange = '30' } = req.query;
    const daysAgo = new Date();
    daysAgo.setDate(daysAgo.getDate() - parseInt(timeRange));

    const recentAttempts = await TestAttempt.find({
      collegeId: req.user.collegeId,
      status: 'completed',
      createdAt: { $gte: daysAgo }
    }).populate('testId', 'testType subject');

    const totalAttempts = recentAttempts.length;
    const avgScore = recentAttempts.length > 0
      ? recentAttempts.reduce((sum, a) => sum + a.percentage, 0) / totalAttempts
      : 0;

    const passedCount = recentAttempts.filter(a => a.percentage >= 40).length;
    const passRate = totalAttempts > 0 ? (passedCount / totalAttempts) * 100 : 0;

    const subjectPerformance = {};
    recentAttempts.forEach(attempt => {
      const subject = attempt.testId?.subject || 'Unknown';
      if (!subjectPerformance[subject]) {
        subjectPerformance[subject] = {
          attempts: 0,
          totalScore: 0,
          passed: 0
        };
      }
      subjectPerformance[subject].attempts += 1;
      subjectPerformance[subject].totalScore += attempt.percentage;
      if (attempt.percentage >= 40) {
        subjectPerformance[subject].passed += 1;
      }
    });

    const subjectStats = Object.entries(subjectPerformance).map(([subject, data]) => ({
      subject,
      attempts: data.attempts,
      avgScore: (data.totalScore / data.attempts).toFixed(1),
      passRate: ((data.passed / data.attempts) * 100).toFixed(1)
    }));

    const testTypeDistribution = {};
    recentAttempts.forEach(attempt => {
      const testType = attempt.testId?.testType || 'Unknown';
      testTypeDistribution[testType] = (testTypeDistribution[testType] || 0) + 1;
    });

    res.json({
      overview: {
        totalAttempts,
        avgScore: avgScore.toFixed(1),
        passRate: passRate.toFixed(1),
        timeRange: parseInt(timeRange)
      },
      subjectStats,
      testTypeDistribution
    });
  } catch (error) {
    logger.errorLog(error, { context: 'Get analytics overview error' });
    res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;
