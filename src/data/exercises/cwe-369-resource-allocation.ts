import type { Exercise } from '@/data/exercises'

export const cwe369ResourceAllocation: Exercise = {
  cweId: 'CWE-369',
  name: 'Divide By Zero - Resource Per User Calculation',

  vulnerableFunction: `function calculateResourcesPerUser(totalResources, activeUsers) {
  // Distribute resources evenly among active users
  const resourcesPerUser = Math.floor(totalResources / activeUsers);

  const allocation = {
    perUser: resourcesPerUser,
    totalAllocated: resourcesPerUser * activeUsers,
    remaining: totalResources - (resourcesPerUser * activeUsers)
  };

  return allocation;
}`,

  vulnerableLine: `const resourcesPerUser = Math.floor(totalResources / activeUsers);`,

  options: [
    {
      code: `if (activeUsers === 0) throw new Error('Cannot allocate resources to zero users'); const resourcesPerUser = Math.floor(totalResources / activeUsers);`,
      correct: true,
      explanation: `Correct! Validating that activeUsers is not zero before division prevents crashes. Following MITRE's guidance on checking denominators prevents the divide by zero error.`
    },
    {
      code: `const resourcesPerUser = Math.floor(totalResources / activeUsers);`,
      correct: false,
      explanation: 'Direct from MITRE: When activeUsers is zero, dividing totalResources by zero causes an application crash. No validation protects against this scenario.'
    },
    {
      code: `const resourcesPerUser = activeUsers > 0 ? Math.floor(totalResources / activeUsers) : totalResources;`,
      correct: false,
      explanation: 'Giving all resources to zero users is logically inconsistent. The function should indicate that allocation is impossible rather than providing misleading results.'
    },
    {
      code: `const resourcesPerUser = Math.floor(totalResources / Math.max(activeUsers, 1));`,
      correct: false,
      explanation: 'Using Math.max(activeUsers, 1) prevents divide by zero but gives incorrect results when there are actually zero users. This masks the real issue rather than handling it properly.'
    },
    {
      code: `const resourcesPerUser = Number.isNaN(totalResources / activeUsers) ? 0 : Math.floor(totalResources / activeUsers);`,
      correct: false,
      explanation: 'Checking for NaN occurs after the division. When activeUsers is zero, the divide by zero exception happens before NaN checking can take place.'
    },
    {
      code: `const resourcesPerUser = activeUsers ? Math.floor(totalResources / activeUsers) : 0;`,
      correct: false,
      explanation: 'Returning 0 resources per user when there are no users is conceptually misleading. It suggests users exist but receive no resources rather than indicating no users are present.'
    },
    {
      code: `const resourcesPerUser = Math.floor(Math.abs(totalResources / activeUsers));`,
      correct: false,
      explanation: 'Math.abs does not prevent divide by zero - the division still occurs first. When activeUsers is zero, this will crash before Math.abs can execute.'
    },
    {
      code: `try { const resourcesPerUser = Math.floor(totalResources / activeUsers); } catch { const resourcesPerUser = 0; }`,
      correct: false,
      explanation: 'Using try-catch handles the exception after it occurs rather than preventing it. Better design validates inputs before potentially dangerous operations.'
    }
  ]
}