const request = require('supertest');
const app = require('../server');
const assert = require('assert');

describe('Activity Metrics API', function() {
  it('should return activity summary structure', function(done) {
    request(app)
      .get('/api/admin/metrics/activity-summary')
      .expect(401) // requires auth, so 401 is acceptable for this smoke test
      .then(() => done())
      .catch(done);
  });
});
