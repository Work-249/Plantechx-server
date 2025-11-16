const request = require('supertest');
const app = require('../server');
const assert = require('assert');

describe('Admin Export API', function() {
  it('should stream CSV and match table data', function(done) {
    const sample = [
      { name: 'Alice', score: 90 },
      { name: 'Bob', score: 75 }
    ];

    request(app)
      .post('/api/admin/export')
      .send({ format: 'csv', filename: 'test-export', data: sample })
      .expect('Content-Type', /text\/csv/)
      .expect(200)
      .then(res => {
        const text = res.text;
        // first line should be header
        const lines = text.trim().split(/\r?\n/);
        assert(lines[0].includes('name'));
        assert(lines[1].includes('Alice'));
        assert(lines[2].includes('Bob'));
        done();
      }).catch(done);
  });
});
