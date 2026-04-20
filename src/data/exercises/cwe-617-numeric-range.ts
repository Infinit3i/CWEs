import type { Exercise } from '@/data/exercises'

export const cwe617NumericRange: Exercise = {
  cweId: 'CWE-617',
  name: 'Reachable Assertion - Numeric Range Validation',

  vulnerableFunction: `function processQuantity(userQuantity) {
  const quantity = parseInt(userQuantity);

  // Assert valid quantity range
  assert(quantity > 0, 'Quantity must be positive');
  assert(quantity <= 1000, 'Quantity cannot exceed 1000');
  assert(Number.isInteger(quantity), 'Quantity must be whole number');

  return calculateTotal(quantity);
}`,

  vulnerableLine: `assert(quantity > 0, 'Quantity must be positive');`,

  options: [
    {
      code: `if (quantity <= 0) { throw new RangeError('Quantity must be positive'); } if (quantity > 1000) { throw new RangeError('Quantity cannot exceed 1000'); }`,
      correct: true,
      explanation: `Correct! Using explicit range validation with proper exceptions prevents assertions from being triggered by invalid user input while maintaining business logic constraints.`
    },
    {
      code: `assert(quantity > 0, 'Quantity must be positive');`,
      correct: false,
      explanation: 'Direct from MITRE: Negative or zero quantities provided by users trigger this assertion, causing application crashes. Input validation should not rely on assertions.'
    },
    {
      code: `assert(quantity && quantity > 0 && quantity <= 1000);`,
      correct: false,
      explanation: 'Combining multiple conditions in a single assertion creates multiple ways for user input to cause crashes. Any invalid quantity value triggers the assertion.'
    },
    {
      code: `if (userQuantity) { assert(quantity > 0); assert(quantity <= 1000); }`,
      correct: false,
      explanation: 'Conditional assertions still allow valid input to trigger crashes. Users providing defined but invalid quantities can still cause assertion failures.'
    },
    {
      code: `assert(typeof quantity === 'number' && quantity > 0);`,
      correct: false,
      explanation: 'Type checking in assertions creates additional failure modes. Both type violations and invalid ranges can trigger crashes through user input.'
    },
    {
      code: `try { assert(quantity > 0 && quantity <= 1000); } catch (AssertionError) { return 0; }`,
      correct: false,
      explanation: 'Catching assertion errors after execution is inefficient and masks input validation issues. Use proper validation before processing instead.'
    },
    {
      code: `const isValidQuantity = quantity > 0 && quantity <= 1000; assert(isValidQuantity, 'Invalid quantity');`,
      correct: false,
      explanation: 'Moving validation to a variable does not prevent user input from controlling assertion execution. Invalid quantities still trigger the assertion.'
    },
    {
      code: `assert(Math.abs(quantity) === quantity && quantity <= 1000);`,
      correct: false,
      explanation: 'Using mathematical functions in assertions still allows user input to trigger crashes. Negative quantities or values exceeding limits cause assertion failures.'
    }
  ]
}