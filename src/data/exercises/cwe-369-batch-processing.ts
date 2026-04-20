import type { Exercise } from '@/data/exercises'

export const cwe369BatchProcessing: Exercise = {
  cweId: 'CWE-369',
  name: 'Divide By Zero - Batch Processing Rate',

  vulnerableFunction: `function calculateProcessingRate(itemsProcessed, timeElapsedSeconds) {
  // Calculate items per second processing rate
  const itemsPerSecond = itemsProcessed / timeElapsedSeconds;

  return {
    rate: itemsPerSecond.toFixed(2),
    itemsProcessed: itemsProcessed,
    timeElapsed: timeElapsedSeconds,
    estimatedCompletion: itemsPerSecond > 0 ? 'Normal' : 'Stalled'
  };
}`,

  vulnerableLine: `const itemsPerSecond = itemsProcessed / timeElapsedSeconds;`,

  options: [
    {
      code: `if (timeElapsedSeconds === 0) { return { rate: 'Instantaneous', itemsProcessed: itemsProcessed, timeElapsed: timeElapsedSeconds, estimatedCompletion: 'Instant' }; } const itemsPerSecond = itemsProcessed / timeElapsedSeconds;`,
      correct: true,
      explanation: `Correct! Checking for zero timeElapsedSeconds and providing a meaningful response for instantaneous processing prevents crashes while handling the edge case appropriately.`
    },
    {
      code: `const itemsPerSecond = itemsProcessed / timeElapsedSeconds;`,
      correct: false,
      explanation: 'Direct from MITRE: When timeElapsedSeconds is zero (instantaneous or measurement error), this division causes an application crash. Input validation is needed.'
    },
    {
      code: `const itemsPerSecond = timeElapsedSeconds > 0 ? itemsProcessed / timeElapsedSeconds : itemsProcessed * 1000;`,
      correct: false,
      explanation: 'Multiplying by 1000 when time is zero creates arbitrary rate values. This does not represent actual processing speed and provides misleading performance metrics.'
    },
    {
      code: `const itemsPerSecond = itemsProcessed / (timeElapsedSeconds + 0.001);`,
      correct: false,
      explanation: 'Adding a small value prevents divide by zero but produces incorrect rates when processing is truly instantaneous. This skews performance measurements.'
    },
    {
      code: `const itemsPerSecond = timeElapsedSeconds === 0 ? 0 : itemsProcessed / timeElapsedSeconds;`,
      correct: false,
      explanation: 'Returning 0 items per second when processing is instantaneous is incorrect. Zero rate suggests no processing occurred rather than very fast processing.'
    },
    {
      code: `const itemsPerSecond = Math.min(itemsProcessed / timeElapsedSeconds, Number.MAX_VALUE);`,
      correct: false,
      explanation: 'Math.min does not prevent divide by zero - the division occurs first. When timeElapsedSeconds is zero, this crashes before Math.min executes.'
    },
    {
      code: `const itemsPerSecond = isNaN(itemsProcessed / timeElapsedSeconds) ? -1 : itemsProcessed / timeElapsedSeconds;`,
      correct: false,
      explanation: 'Checking for NaN requires performing the division first. When timeElapsedSeconds is zero, the divide by zero exception happens before NaN checking.'
    },
    {
      code: `const itemsPerSecond = timeElapsedSeconds ? itemsProcessed / timeElapsedSeconds : Number.MAX_SAFE_INTEGER;`,
      correct: false,
      explanation: 'Using MAX_SAFE_INTEGER as a default rate is misleading and could break downstream calculations that depend on realistic processing rate values.'
    }
  ]
}