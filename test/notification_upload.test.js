const request = require('supertest');
const app = require('../server');
const assert = require('assert');
const path = require('path');
const fs = require('fs');
const Notification = require('../models/Notification');

describe('Notification upload integration', function() {
  it('should create notification with attachment and set attachmentUrl', async function() {
    this.timeout(10000);

    const agent = request(app);

    // Login as master admin (created at DB startup)
    const loginRes = await agent
      .post('/api/auth/login')
      .send({ email: 'carelinkdesk@gmail.com', password: 'admin123' })
      .expect(200);

    const token = loginRes.body.token;

    // Ensure fixtures directory exists and write a small PNG fixture
    const fixturesDir = path.join(__dirname, 'fixtures');
    if (!fs.existsSync(fixturesDir)) fs.mkdirSync(fixturesDir, { recursive: true });

    // 1x1 transparent PNG base64
    const pngBase64 = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMB/6X6J0QAAAAASUVORK5CYII=';
    const pngPath = path.join(fixturesDir, 'test-image.png');
    fs.writeFileSync(pngPath, Buffer.from(pngBase64, 'base64'));

    const res = await agent
      .post('/api/notifications')
      .set('Authorization', `Bearer ${token}`)
      .field('title', 'Integration Test Notification')
      .field('message', 'This is a test message for integration with attachment')
      .field('type', 'general')
      .field('priority', 'medium')
      .field('targetType', 'students')
      .attach('attachment', pngPath)
      .expect(201);

    // Ensure notification exists and attachmentUrl was saved
    const notif = await Notification.findOne({ title: 'Integration Test Notification' });
    assert(notif, 'Notification should be saved');
    assert(notif.attachmentUrl, 'attachmentUrl should be present on notification');
    assert.notStrictEqual(notif.attachmentUrl, '');
  });
});
