const request = require('supertest');
const app = require('../server');
const assert = require('assert');
const PendingAction = require('../models/PendingAction');
const AuditLog = require('../models/AuditLog');
const User = require('../models/User');
const path = require('path');

describe('Master Admin profile email change flow', function() {
  this.timeout(10000);

  let agent;
  let token;
  let masterAdmin;

  before(async function() {
    agent = request(app);
    const loginRes = await agent.post('/api/auth/login').send({ email: 'carelinkdesk@gmail.com', password: 'admin123' }).expect(200);
    token = loginRes.body.token;
    masterAdmin = await User.findOne({ email: 'carelinkdesk@gmail.com' });
    assert(masterAdmin);
  });

  it('should create a pending action and send confirmation for new email', async function() {
  const newEmail = 'new-master-admin@example.com';
  const res = await agent.post('/api/admin/profile/change-email').set('Authorization', `Bearer ${token}`).send({ newEmail }).expect(200);
    assert(res.body.message);

    // Find pending action
    const pending = await PendingAction.findOne({ userId: masterAdmin._id, newEmail, type: 'email_change' });
    assert(pending, 'PendingAction should exist');
    token = pending.token;
  });

  it('should confirm the token and update master admin email and create audit log', async function() {
    if (!token) this.skip();

  const res = await agent.get(`/api/admin/profile/confirm-email-change?token=${token}`).expect(200);
    assert(res.body.message);

    // Refresh user
    const updated = await User.findById(masterAdmin._id);
    assert.strictEqual(updated.email, 'new-master-admin@example.com');

    const audit = await AuditLog.findOne({ userId: masterAdmin._id, action: 'email_change' });
    assert(audit, 'Audit log should be created');
    assert(audit.details && audit.details.newEmail);
  });

  after(async function() {
    // Clean up: revert email back to original
    await User.findByIdAndUpdate(masterAdmin._id, { email: 'carelinkdesk@gmail.com' });
    await PendingAction.deleteMany({ userId: masterAdmin._id });
    await AuditLog.deleteMany({ userId: masterAdmin._id, action: 'email_change' });
  });
});
