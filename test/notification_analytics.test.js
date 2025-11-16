const request = require('supertest');
const app = require('../server');
const assert = require('assert');

describe('Notification Analytics API (smoke)', function() {
  it('should return analytics report structure', function(done) {
    request(app)
      .get('/api/notifications/analytics/report')
      .expect(200)
      .then(res => {
        assert(res.body.summary !== undefined, 'summary should be present');
        assert(Array.isArray(res.body.notifications), 'notifications should be array');
        assert(Array.isArray(res.body.dailyAnalytics), 'dailyAnalytics should be array');
        done();
      }).catch(done);
  });
});
