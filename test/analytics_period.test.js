const assert = require('assert');
const { getPeriodDates } = require('../routes/analytics');

describe('Analytics period helper', function() {
  it('should return periodStart and previousPeriodStart separated by the requested number of days', function() {
    const days = 7;
    const { now, periodStart, previousPeriodStart } = getPeriodDates(days);

    assert(now instanceof Date, 'now should be a Date');
    assert(periodStart instanceof Date, 'periodStart should be a Date');
    assert(previousPeriodStart instanceof Date, 'previousPeriodStart should be a Date');

    const msPerDay = 24 * 60 * 60 * 1000;

    // Allow one second of drift
    const diffNowPeriod = Math.round((now.getTime() - periodStart.getTime()) / msPerDay);
    const diffPeriodPrev = Math.round((periodStart.getTime() - previousPeriodStart.getTime()) / msPerDay);

    assert.strictEqual(diffNowPeriod, days, `expected now - periodStart to be ${days} days but got ${diffNowPeriod}`);
    assert.strictEqual(diffPeriodPrev, days, `expected periodStart - previousPeriodStart to be ${days} days but got ${diffPeriodPrev}`);
  });
});
