// Utility to clean orphaned TestAssignment records
// Run this script with: node utils/cleanupOrphanedTestAssignments.js

const mongoose = require('mongoose');
require('dotenv').config();

const TestAssignment = require('../models/TestAssignment');
const Test = require('../models/Test');
const College = require('../models/College');

async function cleanupOrphanedTestAssignments() {
  await mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });
  console.log('Connected to MongoDB');

  const assignments = await TestAssignment.find({ isActive: true });
  let removed = 0;

  for (const assignment of assignments) {
    const testExists = await Test.exists({ _id: assignment.testId, isActive: true });
    const collegeExists = await College.exists({ _id: assignment.collegeId, isActive: true });
    if (!testExists || !collegeExists) {
      await TestAssignment.deleteOne({ _id: assignment._id });
      removed++;
      console.log(`Removed orphaned assignment: ${assignment._id}`);
    }
  }

  console.log(`Cleanup complete. Removed ${removed} orphaned assignments.`);
  mongoose.disconnect();
}

cleanupOrphanedTestAssignments().catch(err => {
  console.error('Error during cleanup:', err);
  mongoose.disconnect();
});
