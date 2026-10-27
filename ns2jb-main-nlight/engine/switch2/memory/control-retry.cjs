'use strict';

// Bounded recovery of a fully validated, deliberately aborted initial control.
// A recovery failure propagates immediately; it must never trigger a replay.
async function runInitialControl(attempt, recover) {
  for (let index = 1; index <= 3; index++) {
    try { return await attempt(); }
    catch (error) {
      if (error.retryablePinControl !== true || index === 3) throw error;
      await recover(error, index);
    }
  }
}

module.exports = {runInitialControl};
