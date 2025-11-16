const request = require('supertest');
const app = require('../server');
const assert = require('assert');
const Test = require('../models/Test');
const User = require('../models/User');
const mongoose = require('mongoose');

describe('Test edit/load endpoints', function() {
  this.timeout(10000);

  let adminUser = null;
  let createdTestId = null;

  before(async function() {
    adminUser = await User.findOne({ email: 'carelinkdesk@gmail.com' });
    if (!adminUser) throw new Error('Master admin user not found in DB (carelinkdesk@gmail.com)');

    const now = new Date();
    const later = new Date(now.getTime() + 60 * 60 * 1000);

    const t = new Test({
      testName: 'Edit Load Test',
      testDescription: 'Auto-generated test for edit/load',
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

    await t.save();
    createdTestId = t._id.toString();
  });

  after(async function() {
    if (createdTestId) await Test.findByIdAndDelete(createdTestId);
  });

  it('should load an existing test for editing', async function() {
    const agent = request(app);

    const loginRes = await agent
      .post('/api/auth/login')
      .send({ email: 'carelinkdesk@gmail.com', password: 'admin123' })
      .expect(200);

    const token = loginRes.body.token;

    const res = await agent
      .get(`/api/tests/${createdTestId}`)
      .set('Authorization', `Bearer ${token}`)
      .expect(200);

    assert(res.body && res.body._id, 'Test payload expected');
    assert.strictEqual(res.body._id.toString(), createdTestId);
  });

  it('should return 404 for a non-existent test id', async function() {
    const agent = request(app);

    const loginRes = await agent
      .post('/api/auth/login')
      .send({ email: 'carelinkdesk@gmail.com', password: 'admin123' })
      .expect(200);

    const token = loginRes.body.token;
  const fakeId = new mongoose.Types.ObjectId();

    await agent
      .get(`/api/tests/${fakeId.toString()}`)
      .set('Authorization', `Bearer ${token}`)
      .expect(404);
  });
});
