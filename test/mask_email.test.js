const assert = require('assert');
const logger = require('../middleware/logger');

describe('maskEmail helper', () => {
  it('masks a normal email keeping first char and domain', () => {
    const out = logger.maskEmail('alice@example.com');
    assert.strictEqual(out, 'a***@example.com');
  });

  it('handles single-char local part', () => {
    const out = logger.maskEmail('a@domain.co');
    assert.strictEqual(out, 'a***@domain.co');
  });

  it('returns N/A for null/undefined', () => {
    assert.strictEqual(logger.maskEmail(null), 'N/A');
    assert.strictEqual(logger.maskEmail(undefined), 'N/A');
  });

  it('returns *** for malformed addresses', () => {
    assert.strictEqual(logger.maskEmail('not-an-email'), '***');
    // empty string is treated as missing and returns 'N/A'
    assert.strictEqual(logger.maskEmail(''), 'N/A');
  });

  it('returns raw email when masking is disabled', () => {
    // toggle masking off
    const prev = logger.maskingEnabled;
    logger.maskingEnabled = false;
    try {
      const out = logger.maskEmail('bob@example.com');
      assert.strictEqual(out, 'bob@example.com');
    } finally {
      logger.maskingEnabled = prev;
    }
  });
});
