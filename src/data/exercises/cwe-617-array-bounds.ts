import type { Exercise } from '@/data/exercises'

export const cwe617ArrayBounds: Exercise = {
  cweId: 'CWE-617',
  name: 'Reachable Assertion - Array Index Validation',

  vulnerableFunction: `function getItemByIndex(items, userIndex) {
  const index = parseInt(userIndex);

  // Assert valid array index
  assert(index >= 0 && index < items.length, 'Index out of bounds');

  return items[index];
}`,

  vulnerableLine: `assert(index >= 0 && index < items.length, 'Index out of bounds');`,

  options: [
    {
      code: `if (index < 0 || index >= items.length) { throw new RangeError('Index out of bounds'); }`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    {
      code: `assert(index >= 0 && index < items.length, 'Index out of bounds');`,
      correct: false,
      explanation: 'User-controlled index values can trigger this assertion, causing application crashes. Assertions should not be reachable through external input.'
    },
    {
      code: `assert(Number.isInteger(index) && index >= 0 && index < items.length);`,
      correct: false,
      explanation: 'Adding more conditions to the assertion does not solve the core issue. User input still controls whether the assertion triggers, creating a denial of service vector.'
    },
    {
      code: `if (items.length > 0) assert(index >= 0 && index < items.length);`,
      correct: false,
      explanation: 'Conditional assertions based on array length still allow user input to control assertion execution when arrays are not empty.'
    },
    {
      code: `const validIndex = index >= 0 && index < items.length; assert(validIndex);`,
      correct: false,
      explanation: 'Separating the validation logic does not change that user input ultimately determines the assertion outcome. The assertion remains reachable through malicious indices.'
    },
    {
      code: `try { assert(index >= 0 && index < items.length); } catch (AssertionError) { return undefined; }`,
      correct: false,
      explanation: 'Catching assertion errors allows the assertion to execute, which is inefficient and maintains the problematic pattern of using assertions for input validation.'
    },
    {
      code: `assert(typeof index === 'number', 'Index must be number'); assert(index >= 0 && index < items.length);`,
      correct: false,
      explanation: 'Multiple assertions create additional attack vectors. Both type checking and range validation assertions can be triggered by crafted user input.'
    },
    {
      code: `if (index !== undefined) assert(index >= 0 && index < items.length);`,
      correct: false,
      explanation: 'Undefined checking does not prevent the assertion from being triggered. Users can still provide defined but invalid index values to crash the application.'
    }
  ]
}