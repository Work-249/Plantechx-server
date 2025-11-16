const request = require('supertest');
const app = require('../server');
const assert = require('assert');
const CodingQuestion = require('../models/CodingQuestion');
const CodingTestCase = require('../models/CodingTestCase');
const User = require('../models/User');
const path = require('path');
const fs = require('fs');

describe('Coding questions import and edit prefill', function() {
  this.timeout(10000);

  let createdQuestionIds = [];

  it('should import multiple questions from JSON file', async function() {
    const agent = request(app);

    const loginRes = await agent
      .post('/api/auth/login')
      .send({ email: 'carelinkdesk@gmail.com', password: 'admin123' })
      .expect(200);

    const token = loginRes.body.token;

    // create a small JSON file fixture
    const fixture = [
      { title: 'Import Q1', description: 'Desc 1', difficulty: 'easy', test_cases: [{ input: '1', expected_output: '1' }] },
      { title: 'Import Q2', description: 'Desc 2', difficulty: 'medium', test_cases: [{ input: '2', expected_output: '2' }] }
    ];

    const fixturesDir = path.join(__dirname, 'fixtures');
    if (!fs.existsSync(fixturesDir)) fs.mkdirSync(fixturesDir, { recursive: true });
    const jsonPath = path.join(fixturesDir, 'import-questions.json');
    fs.writeFileSync(jsonPath, JSON.stringify(fixture));

    const res = await agent
      .post('/api/coding-questions/import')
      .set('Authorization', `Bearer ${token}`)
      .attach('file', jsonPath)
      .expect(200);

    assert(res.body && res.body.results, 'Import results expected');
    assert.strictEqual(res.body.results.successful, 2);

    // Fetch created questions and cleanup
    const created = await CodingQuestion.find({ title: /Import Q/ });
    created.forEach(q => createdQuestionIds.push(q._id));
    assert(created.length >= 2);
  });

  it('should return prefill data for an existing coding question', async function() {
    if (createdQuestionIds.length === 0) this.skip();

    const agent = request(app);
    const loginRes = await agent
      .post('/api/auth/login')
      .send({ email: 'carelinkdesk@gmail.com', password: 'admin123' })
      .expect(200);
    const token = loginRes.body.token;

    const qid = createdQuestionIds[0].toString();
    const res = await agent
      .get(`/api/coding-questions/${qid}/edit`)
      .set('Authorization', `Bearer ${token}`)
      .expect(200);

    assert(res.body && res.body.question, 'Question prefill expected');
    assert.strictEqual(res.body.question.title, 'Import Q1');
  });

  after(async function() {
    if (createdQuestionIds.length > 0) {
      await CodingTestCase.deleteMany({ question_id: { $in: createdQuestionIds } });
      await CodingQuestion.deleteMany({ _id: { $in: createdQuestionIds } });
    }
  });
});
