import type { Exercise } from '@/data/exercises'

export const cwe369RatioCalculation: Exercise = {
  cweId: 'CWE-369',
  name: 'Divide By Zero - Error Rate Ratio',

  vulnerableFunction: `function calculateErrorRatio(errorCount, successCount) {
  // Calculate ratio of errors to successful operations
  const errorRatio = errorCount / successCount;

  return {
    ratio: errorRatio,
    description: errorRatio > 0.1 ? 'High error rate' : 'Acceptable error rate',
    errors: errorCount,
    successes: successCount
  };
}`,

  vulnerableLine: `const errorRatio = errorCount / successCount;`,

  options: [
    {
      code: `if (successCount === 0) { return { ratio: Infinity, description: 'No successful operations', errors: errorCount, successes: successCount }; } const errorRatio = errorCount / successCount;`,
      correct: true,
      explanation: `Correct! Checking for zero successCount and returning Infinity (mathematically correct for division by zero) with appropriate description prevents crashes while providing meaningful information.`
    },
    {
      code: `const errorRatio = errorCount / successCount;`,
      correct: false,
      explanation: 'Direct from MITRE: When successCount is zero, this division causes an application crash. The function needs to validate the denominator before performing division.'
    },
    {
      code: `const errorRatio = successCount === 0 ? 0 : errorCount / successCount;`,
      correct: false,
      explanation: 'Returning 0 when there are no successful operations is mathematically incorrect. Zero successes with errors should indicate infinite or undefined error rate, not zero.'
    },
    {
      code: `const errorRatio = errorCount / (successCount || 1);`,
      correct: false,
      explanation: 'Defaulting successCount to 1 when it is zero produces incorrect ratio calculations. This masks the real issue that no successful operations occurred.'
    },
    {
      code: `const errorRatio = Math.abs(errorCount / successCount);`,
      correct: false,
      explanation: 'Math.abs does not prevent divide by zero - the division happens first. When successCount is zero, this will crash before Math.abs can execute.'
    },
    {
      code: `const errorRatio = successCount > 0 ? errorCount / successCount : 1;`,
      correct: false,
      explanation: 'Returning ratio of 1 (100% error rate) when no successful operations occurred is misleading. This suggests equal errors and successes rather than indicating no successes.'
    },
    {
      code: `const errorRatio = Number.isFinite(errorCount / successCount) ? errorCount / successCount : 0;`,
      correct: false,
      explanation: 'Number.isFinite check requires performing the division first. When successCount is zero, the divide by zero exception occurs before the finite check.'
    },
    {
      code: `const errorRatio = (errorCount + successCount) === 0 ? 0 : errorCount / successCount;`,
      correct: false,
      explanation: 'This checks if both values are zero but still allows division by zero when successCount alone is zero. The condition does not prevent the core issue.'
    }
  ]
}