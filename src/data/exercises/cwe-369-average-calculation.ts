import type { Exercise } from '@/data/exercises'

export const cwe369AverageCalculation: Exercise = {
  cweId: 'CWE-369',
  name: 'Divide By Zero - Response Time Calculation',
  language: 'Go',

  vulnerableFunction: `function computeAverageResponseTime(totalTime, numRequests) {
  // Calculate average response time in milliseconds
  const averageTime = totalTime / numRequests;

  return {
    average: averageTime,
    total: totalTime,
    count: numRequests
  };
}`,

  vulnerableLine: `const averageTime = totalTime / numRequests;`,

  options: [
    {
      code: `if (numRequests === 0) throw new Error('Cannot compute average with zero requests'); const averageTime = totalTime / numRequests;`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    {
      code: `const averageTime = totalTime / numRequests;`,
      correct: false,
      explanation: 'No validation ensures numRequests is not zero. This causes ArithmeticException when computing average of zero requests, crashing the application.'
    },
    {
      code: `const averageTime = numRequests > 0 ? totalTime / numRequests : totalTime;`,
      correct: false,
      explanation: 'Using totalTime when numRequests is zero gives misleading results. The average should be undefined or an error rather than returning the total time value.'
    },
    {
      code: `const averageTime = Math.max(totalTime / numRequests, 0);`,
      correct: false,
      explanation: 'Math.max does not prevent divide by zero - the division still occurs first. This will still crash when numRequests is zero.'
    },
    {
      code: `const averageTime = totalTime / (numRequests || 1);`,
      correct: false,
      explanation: 'Defaulting to 1 when numRequests is falsy gives incorrect mathematical results. Zero requests should not produce an average equal to total time.'
    },
    {
      code: `try { const averageTime = totalTime / numRequests; } catch (e) { return null; }`,
      correct: false,
      explanation: 'While this catches the exception, it occurs after the divide by zero. Better to prevent the division entirely through input validation.'
    },
    {
      code: `const averageTime = isNaN(totalTime / numRequests) ? 0 : totalTime / numRequests;`,
      correct: false,
      explanation: 'Checking for NaN still requires performing the division first. When numRequests is zero, the division by zero exception occurs before NaN checking.'
    },
    {
      code: `const averageTime = totalTime / Math.abs(numRequests);`,
      correct: false,
      explanation: 'Math.abs converts negative values to positive but does not handle zero. When numRequests is zero, Math.abs(0) is still zero, causing divide by zero.'
    }
  ]
}