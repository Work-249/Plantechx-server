const request = require('supertest');
const app = require('../server');
const assert = require('assert');
const Test = require('../models/Test');
const User = require('../models/User');

describe('Analytics dashboard testCounts', function() {
  this.timeout(10000);

  let adminUser = null;
  const createdTests = [];

  before(async function() {
    // Find seeded master admin
    adminUser = await User.findOne({ email: 'carelinkdesk@gmail.com' });
    if (!adminUser) throw new Error('Master admin user not found in DB (carelinkdesk@gmail.com)');

    // Create a couple of test documents to ensure counts change predictably
    const now = new Date();
    const later = new Date(now.getTime() + 60 * 60 * 1000);

    const t1 = new Test({
      testName: 'Analytics Test 1',
      testDescription: 'Auto-generated test for analytics count',
      subject: 'Verbal',
      testType: 'Assessment',
      numberOfQuestions: 1,
      marksPerQuestion: 1,
      duration: 10,
      startDateTime: now,
      endDateTime: later,
      questions: [{ questionText: 'Q1', options: { A: 'a', B: 'b', C: 'c', D:'d' }, correctAnswer: 'A', marks: 1 }],
      createdBy: adminUser._id,
      isActive: true
    });

    const t2 = new Test({
      testName: 'Analytics Test 2',
      testDescription: 'Auto-generated test for analytics count',
      subject: 'Technical',
      testType: 'Practice',
      numberOfQuestions: 1,
      marksPerQuestion: 1,
      duration: 10,
      startDateTime: now,
      endDateTime: later,
      questions: [{ questionText: 'Q1', options: { A: 'a', B: 'b', C: 'c', D:'d' }, correctAnswer: 'A', marks: 1 }],
      createdBy: adminUser._id,
      isActive: true
    });

    await t1.save();
    await t2.save();

    createdTests.push(t1._id, t2._id);
  });

  after(async function() {
    // cleanup created tests
    if (createdTests.length > 0) await Test.deleteMany({ _id: { $in: createdTests } });
  });

  it('should return testCounts that match DB counts', async function() {
    const agent = request(app);

    const loginRes = await agent
      .post('/api/auth/login')
      .send({ email: 'carelinkdesk@gmail.com', password: 'admin123' })
      .expect(200);

    const token = loginRes.body.token;

    const res = await agent
      .get('/api/analytics/dashboard')
      .set('Authorization', `Bearer ${token}`)
      .expect(200);

    assert(res.body, 'Response body expected');
    const counts = res.body.testCounts;
    assert(counts && typeof counts === 'object', 'testCounts object expected');

    const dbTotal = await Test.countDocuments({ isActive: true });
    assert.strictEqual(counts.total, dbTotal, 'Total test count should match DB count');

    // Assert byType and bySubject keys are numbers and match DB
    const byType = counts.byType || {};
    const bySubject = counts.bySubject || {};

    const dbAssessment = await Test.countDocuments({ testType: 'Assessment', isActive: true });
    const dbPractice = await Test.countDocuments({ testType: 'Practice', isActive: true });
    assert.strictEqual(byType.Assessment, dbAssessment);
    assert.strictEqual(byType.Practice, dbPractice);

    const dbVerbal = await Test.countDocuments({ subject: 'Verbal', isActive: true });
    const dbTechnical = await Test.countDocuments({ subject: 'Technical', isActive: true });
    assert.strictEqual(bySubject.Verbal, dbVerbal);
    assert.strictEqual(bySubject.Technical, dbTechnical);
  });
});
