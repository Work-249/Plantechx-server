const express = require('express');
const User = require('../models/User');
const College = require('../models/College');
const Test = require('../models/Test');
const TestAttempt = require('../models/TestAttempt');
const TestAssignment = require('../models/TestAssignment');
const Notification = require('../models/Notification');
const { auth, authorize } = require('../middleware/auth');
const logger = require('../middleware/logger');

const router = express.Router();

// Master Admin Analytics Dashboard
router.get('/dashboard', auth, authorize('master_admin'), async (req, res) => {
  try {
    logger.info('Fetching dashboard analytics', { userId: req.user._id });

    // Get current date for time-based queries
    const now = new Date();
    const days = parseInt(req.query.days, 10) || 30;
    const periodStart = new Date(now.getTime() - days * 24 * 60 * 60 * 1000);
    const previousPeriodStart = new Date(periodStart.getTime() - days * 24 * 60 * 60 * 1000);

    // Pending Actions
    const pendingCollegeAssignments = await TestAssignment.countDocuments({
      assignedTo: 'college',
      status: 'pending',
      isActive: true
    });
    logger.info('Pending College Assignments:', { pendingCollegeAssignments });

    const collegesNeverLoggedIn = await User.countDocuments({
      role: 'college_admin',
      hasLoggedIn: false,
      isActive: true
    });
    logger.info('Colleges Never Logged In:', { collegesNeverLoggedIn });

    // Platform Growth (last N days)
    const newColleges = await College.countDocuments({
      createdAt: { $gte: periodStart },
      isActive: true
    });

    const newFaculty = await User.countDocuments({
      role: 'faculty',
      createdAt: { $gte: periodStart },
      isActive: true
    });

    const newStudents = await User.countDocuments({
      role: 'student',
      createdAt: { $gte: periodStart },
      isActive: true
    });

    // Recent Platform Activity (last 10 actions)
    const recentColleges = await College.find({ isActive: true })
      .sort({ createdAt: -1 })
      .limit(3)
      .select('name createdAt');

    const recentTests = await Test.find({ isActive: true })
      .sort({ createdAt: -1 })
      .limit(3)
      .select('testName subject createdAt');

    const recentNotifications = await Notification.find({ isActive: true })
      .sort({ createdAt: -1 })
      .limit(2)
      .select('title totalRecipients createdAt');

    const recentLogins = await User.find({
      role: { $in: ['college_admin', 'faculty', 'student'] },
      lastLogin: { $gte: periodStart }
    })
    .populate('collegeId', 'name')
    .sort({ lastLogin: -1 })
    .limit(5)
    .select('name email role lastLogin collegeId');

    // Build recent activity array
    const recentActivity = [];
    
    recentColleges.forEach(college => {
      recentActivity.push({
        id: college._id,
        type: 'college_added',
        description: 'New college registered',
        details: `${college.name} joined the platform`,
        timestamp: college.createdAt,
        icon: 'building'
      });
    });

    recentTests.forEach(test => {
      recentActivity.push({
        id: test._id,
        type: 'test_created',
        description: 'New test created',
        details: `${test.testName} (${test.subject})`,
        timestamp: test.createdAt,
        icon: 'file-text'
      });
    });

    recentNotifications.forEach(notification => {
      recentActivity.push({
        id: notification._id,
        type: 'notification_sent',
        description: 'Notification sent',
        details: `${notification.title} to ${notification.totalRecipients} recipients`,
        timestamp: notification.createdAt,
        icon: 'bell'
      });
    });

    recentLogins.forEach(login => {
      recentActivity.push({
        id: login._id,
        type: 'user_login',
        description: 'User logged in',
        details: `${login.name} (${login.role}) from ${login.collegeId?.name || 'Unknown'}`,
        timestamp: login.lastLogin,
        icon: 'user'
      });
    });

    // Sort by timestamp and take last 10
    recentActivity.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
    const last10Activities = recentActivity.slice(0, 10);

    // Current Statistics
    const totalColleges = await College.countDocuments({ isActive: true });
    const totalStudents = await User.countDocuments({ role: 'student', isActive: true });
    const totalFaculty = await User.countDocuments({ role: 'faculty', isActive: true });

    // Active Exams (tests currently running)
    const activeExams = await Test.countDocuments({
      startDateTime: { $lte: now },
      endDateTime: { $gte: now },
      isActive: true
    });

    // Completed Tests
    const completedTests = await TestAttempt.countDocuments({ isActive: true });

    // Tests completed in current period
    const testsCompletedInPeriod = await TestAttempt.countDocuments({
      createdAt: { $gte: periodStart },
      isActive: true
    });
    logger.info('Tests Completed In Period:', { testsCompletedInPeriod });

    // Calculate growth percentages (comparing with previous 30 days)
    const prevColleges = await College.countDocuments({
      createdAt: { $gte: previousPeriodStart, $lt: periodStart },
      isActive: true
    });

    const prevStudents = await User.countDocuments({
      role: 'student',
      createdAt: { $gte: previousPeriodStart, $lt: periodStart },
      isActive: true
    });

    const prevTests = await TestAttempt.countDocuments({
      createdAt: { $gte: previousPeriodStart, $lt: periodStart },
      isActive: true
    });

    const collegeGrowth = prevColleges > 0 ? ((newColleges - prevColleges) / prevColleges * 100) : 100;
    const studentGrowth = prevStudents > 0 ? ((newStudents - prevStudents) / prevStudents * 100) : 100;
  const testCompletionGrowth = prevTests > 0 ? ((testsCompletedInPeriod - prevTests) / prevTests * 100) : 100;

    const analyticsData = {
      overview: {
        totalColleges,
        totalStudents,
        totalFaculty,
        activeExams,
        completedTests
      },
      // Add authoritative test counts so dashboard can trust server-side numbers
      testCounts: {
        total: await Test.countDocuments({ isActive: true }),
        byType: {
          Assessment: await Test.countDocuments({ testType: 'Assessment', isActive: true }),
          Practice: await Test.countDocuments({ testType: 'Practice', isActive: true }),
          'Mock Test': await Test.countDocuments({ testType: 'Mock Test', isActive: true }),
          'Specific Company Test': await Test.countDocuments({ testType: 'Specific Company Test', isActive: true })
        },
        bySubject: {
          Verbal: await Test.countDocuments({ subject: 'Verbal', isActive: true }),
          Reasoning: await Test.countDocuments({ subject: 'Reasoning', isActive: true }),
          Technical: await Test.countDocuments({ subject: 'Technical', isActive: true }),
          Arithmetic: await Test.countDocuments({ subject: 'Arithmetic', isActive: true }),
          Communication: await Test.countDocuments({ subject: 'Communication', isActive: true })
        }
      },
      pendingActions: {
        collegeAssignments: pendingCollegeAssignments,
        newCollegeCredentials: collegesNeverLoggedIn,
        testsCompletedInPeriod
      },
      platformGrowth: {
        newColleges,
        newFaculty,
        newStudents,
        collegeGrowthPercentage: Math.round(collegeGrowth),
        studentGrowthPercentage: Math.round(studentGrowth),
        testCompletionGrowthPercentage: Math.round(testCompletionGrowth)
      },
      recentActivity: last10Activities.map(activity => ({
        ...activity,
        timeAgo: getTimeAgo(activity.timestamp)
      })),
      recentLogins
    };

    logger.info('Dashboard analytics fetched successfully', {
      totalColleges,
      totalStudents,
      activeExams,
      recentActivityCount: last10Activities.length
    });

    res.json(analyticsData);

  } catch (error) {
    logger.errorLog(error, { context: 'Dashboard Analytics', userId: req.user?._id });
    res.status(500).json({ error: 'Failed to fetch dashboard analytics' });
  }
});

// College Admin Analytics
router.get('/college-dashboard', auth, authorize('college_admin'), async (req, res) => {
  try {
    const collegeId = req.user.collegeId;
    const now = new Date();
    const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);

    // Basic counts
    const totalFaculty = await User.countDocuments({
      collegeId,
      role: 'faculty',
      isActive: true
    });

    const totalStudents = await User.countDocuments({
      collegeId,
      role: 'student',
      isActive: true
    });

    // Test statistics
    const assignedTests = await TestAssignment.countDocuments({
      collegeId,
      status: 'accepted',
      isActive: true
    });

    const completedTests = await TestAttempt.countDocuments({
      collegeId,
      isActive: true
    });

    // Recent activity
    const recentUsers = await User.find({
      collegeId,
      role: { $in: ['faculty', 'student'] },
      createdAt: { $gte: thirtyDaysAgo }
    })
    .sort({ createdAt: -1 })
    .limit(5)
    .select('name role createdAt');

    const recentTestAttempts = await TestAttempt.find({
      collegeId,
      createdAt: { $gte: thirtyDaysAgo }
    })
    .populate('studentId', 'name')
    .populate('testId', 'testName')
    .sort({ createdAt: -1 })
    .limit(5);

    res.json({
      overview: {
        totalFaculty,
        totalStudents,
        assignedTests,
        completedTests
      },
      recentUsers,
      recentTestAttempts
    });

  } catch (error) {
    logger.errorLog(error, { context: 'College Dashboard Analytics', userId: req.user?._id });
    res.status(500).json({ error: 'Failed to fetch college analytics' });
  }
});

// Helper function to calculate time ago
function getTimeAgo(timestamp) {
  const now = new Date();
  const time = new Date(timestamp);
  const diffInMinutes = Math.floor((now.getTime() - time.getTime()) / (1000 * 60));
  
  if (diffInMinutes < 1) return 'Just now';
  if (diffInMinutes < 60) return `${diffInMinutes}m ago`;
  if (diffInMinutes < 1440) return `${Math.floor(diffInMinutes / 60)}h ago`;
  return `${Math.floor(diffInMinutes / 1440)}d ago`;
}

function getPeriodDates(days = 30) {
  const now = new Date();
  const periodStart = new Date(now.getTime() - days * 24 * 60 * 60 * 1000);
  const previousPeriodStart = new Date(periodStart.getTime() - days * 24 * 60 * 60 * 1000);
  return { now, periodStart, previousPeriodStart };
}

// Attach helper to router so tests can access it
router.getPeriodDates = getPeriodDates;

module.exports = router;