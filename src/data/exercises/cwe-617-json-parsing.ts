import type { Exercise } from '@/data/exercises'

export const cwe617JsonParsing: Exercise = {
  cweId: 'CWE-617',
  name: 'Reachable Assertion - JSON Structure Validation',

  vulnerableFunction: `function processApiRequest(requestBody) {
  const data = JSON.parse(requestBody);

  // Assert required structure
  assert(data.hasOwnProperty('action'), 'Action field required');
  assert(data.action.length > 0, 'Action cannot be empty');
  assert(Array.isArray(data.parameters), 'Parameters must be array');

  return executeAction(data.action, data.parameters);
}`,

  vulnerableLine: `assert(data.hasOwnProperty('action'), 'Action field required');`,

  options: [
    {
      code: `if (!data.hasOwnProperty('action')) { throw new Error('Action field required'); } if (!data.action || data.action.length === 0) { throw new Error('Action cannot be empty'); }`,
      correct: true,
      explanation: `Correct! Using explicit checks with proper error throwing prevents assertions from being triggered by malformed JSON while providing clear error messages for API clients.`
    },
    {
      code: `assert(data.hasOwnProperty('action'), 'Action field required');`,
      correct: false,
      explanation: 'Direct from MITRE: Malformed JSON without action field triggers this assertion, causing server crashes. API input validation should use proper error responses, not assertions.'
    },
    {
      code: `assert(data && data.hasOwnProperty('action'), 'Valid data with action required');`,
      correct: false,
      explanation: 'Adding null checks to assertions does not prevent user input from triggering crashes. Malformed JSON structures can still cause the assertion to fail.'
    },
    {
      code: `if (data) { assert(data.hasOwnProperty('action')); assert(Array.isArray(data.parameters)); }`,
      correct: false,
      explanation: 'Conditional assertions still allow malformed but valid JSON to trigger assertion failures. The core issue of using assertions for input validation remains.'
    },
    {
      code: `assert(typeof data === 'object' && data.hasOwnProperty('action'));`,
      correct: false,
      explanation: 'Type checking in assertions creates additional failure modes. Both invalid types and missing action fields can trigger crashes through user input.'
    },
    {
      code: `try { assert(data.hasOwnProperty('action')); } catch (e) { throw new Error('Invalid request format'); }`,
      correct: false,
      explanation: 'Catching assertion errors after execution is inefficient and maintains the problematic pattern of using assertions for input validation.'
    },
    {
      code: `const hasAction = data && data.hasOwnProperty('action'); assert(hasAction, 'Action field missing');`,
      correct: false,
      explanation: 'Moving validation to a variable does not prevent user input from controlling the assertion outcome. Missing action fields still trigger crashes.'
    },
    {
      code: `assert(Object.keys(data).includes('action'), 'Action property required');`,
      correct: false,
      explanation: 'Using different property checking methods does not solve the core issue. User-provided JSON without action fields still triggers the assertion and crashes the application.'
    }
  ]
}