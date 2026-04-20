import type { Exercise } from '@/data/exercises'

export const cwe20BoardDimensions: Exercise = {
  cweId: 'CWE-20',
  name: 'Improper Input Validation - Game Board Allocation',

  vulnerableFunction: `function createGameBoard(width, height) {
  const MAX_DIMENSION = 1000;

  // Validate board dimensions
  if (width > MAX_DIMENSION || height > MAX_DIMENSION) {
    throw new Error('Board dimensions too large');
  }

  // Allocate game board
  const totalSquares = width * height;
  const board = new Array(totalSquares);

  // Initialize board squares
  for (let i = 0; i < totalSquares; i++) {
    board[i] = { occupied: false, piece: null };
  }

  return {
    width,
    height,
    squares: board,
    totalSquares
  };
}`,

  vulnerableLine: `const totalSquares = width * height;`,

  options: [
    {
      code: `if (width > 0 && height > 0 && width <= MAX_DIMENSION && height <= MAX_DIMENSION) { const totalSquares = width * height; } else { throw new Error('Invalid dimensions'); }`,
      correct: true,
      explanation: `Correct! Validating that both dimensions are positive prevents negative values that could cause integer overflow in multiplication. This ensures array allocation uses valid positive sizes and prevents memory allocation issues.`
    },
    {
      code: `const totalSquares = width * height;`,
      correct: false,
      explanation: 'MITRE integer overflow pattern: Only validates positive overflow, missing negative values. Large negative dimensions (-1000000) cause integer overflow in multiplication, potentially allocating unexpected memory amounts or causing crashes.'
    },
    {
      code: `if (width < MAX_DIMENSION && height < MAX_DIMENSION) { const totalSquares = width * height; }`,
      correct: false,
      explanation: 'Incomplete validation allows zero and negative values. Negative dimensions can cause integer overflow while zero dimensions create empty boards that break game logic assumptions.'
    },
    {
      code: `const totalSquares = Math.abs(width) * Math.abs(height);`,
      correct: false,
      explanation: 'Math.abs() masks invalid input instead of rejecting it. User providing negative dimensions should receive validation error, not automatic conversion to positive values.'
    },
    {
      code: `if (width !== 0 && height !== 0) { const totalSquares = width * height; }`,
      correct: false,
      explanation: 'Zero check insufficient - allows negative values. Large negative dimensions can cause integer overflow in multiplication, leading to unexpected memory allocation behavior.'
    },
    {
      code: `const safeWidth = Math.max(1, width); const safeHeight = Math.max(1, height); const totalSquares = safeWidth * safeHeight;`,
      correct: false,
      explanation: 'Automatic correction silently changes user intent. Invalid input should trigger validation errors for proper error handling rather than silent modification.'
    },
    {
      code: `if (typeof width === 'number' && typeof height === 'number') { const totalSquares = width * height; }`,
      correct: false,
      explanation: 'Type checking allows negative numbers and zero. These values are valid numbers but create business logic issues and potential integer overflow vulnerabilities.'
    },
    {
      code: `try { const totalSquares = width * height; const board = new Array(totalSquares); } catch(e) { throw new Error('Allocation failed'); }`,
      correct: false,
      explanation: 'Exception handling after overflow is too late. Integer overflow occurs during multiplication before array allocation, potentially causing unexpected behavior.'
    },
    {
      code: `const totalSquares = Math.min(width * height, MAX_DIMENSION * MAX_DIMENSION);`,
      correct: false,
      explanation: 'Clamping result does not prevent integer overflow in the multiplication itself. Overflow occurs before Math.min() can limit the result value.'
    },
    {
      code: `if (isFinite(width) && isFinite(height)) { const totalSquares = width * height; }`,
      correct: false,
      explanation: 'Finite check allows negative numbers and zero. These values can cause integer overflow or create invalid board states that break game logic.'
    }
  ]
}