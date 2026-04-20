import type { Exercise } from '@/data/exercises'

export const cwe369PercentageCalculation: Exercise = {
  cweId: 'CWE-369',
  name: 'Divide By Zero - Success Rate Percentage',

  vulnerableFunction: `function calculateSuccessRate(successfulOperations, totalOperations) {
  // Calculate percentage of successful operations
  const successRate = (successfulOperations * 100) / totalOperations;

  return {
    percentage: successRate.toFixed(2),
    successful: successfulOperations,
    total: totalOperations
  };
}`,

  vulnerableLine: `const successRate = (successfulOperations * 100) / totalOperations;`,

  options: [
    {
      code: `if (totalOperations === 0) { return { percentage: 'N/A', successful: successfulOperations, total: totalOperations }; } const successRate = (successfulOperations * 100) / totalOperations;`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    {
      code: `const successRate = (successfulOperations * 100) / totalOperations;`,
      correct: false,
      explanation: 'When totalOperations is zero, this division causes a crash. No validation protects against the zero denominator scenario.'
    },
    {
      code: `const successRate = totalOperations ? (successfulOperations * 100) / totalOperations : 100;`,
      correct: false,
      explanation: 'Returning 100% success rate when no operations occurred is mathematically incorrect and misleading for system monitoring and reporting.'
    },
    {
      code: `const successRate = (successfulOperations * 100) / (totalOperations + 1);`,
      correct: false,
      explanation: 'Adding 1 to the denominator prevents divide by zero but produces incorrect percentages. This artificially skews all success rate calculations.'
    },
    {
      code: `const successRate = totalOperations === 0 ? 0 : (successfulOperations * 100) / totalOperations;`,
      correct: false,
      explanation: 'Returning 0% when no operations occurred is misleading. Zero operations is conceptually different from 0% success rate and should be handled distinctly.'
    },
    {
      code: `const successRate = Math.min((successfulOperations * 100) / totalOperations, 100);`,
      correct: false,
      explanation: 'Math.min does not prevent the divide by zero - the division still executes first. This will crash when totalOperations is zero.'
    },
    {
      code: `const successRate = isFinite(successfulOperations / totalOperations) ? (successfulOperations * 100) / totalOperations : 0;`,
      correct: false,
      explanation: 'The isFinite check requires performing division first. When totalOperations is zero, the initial division will cause the application to crash.'
    },
    {
      code: `const successRate = Number.isInteger(totalOperations) ? (successfulOperations * 100) / totalOperations : 0;`,
      correct: false,
      explanation: 'Checking if totalOperations is an integer does not prevent it from being zero. Zero is a valid integer, so this check does not protect against divide by zero.'
    }
  ]
}