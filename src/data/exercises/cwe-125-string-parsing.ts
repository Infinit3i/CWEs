import type { Exercise } from '@/data/exercises'

export const cwe125StringParsing: Exercise = {
  cweId: 'CWE-125',
  name: 'Out-of-bounds Read - String Token Parser',

  vulnerableFunction: `function parseTokenString(inputString, tokenIndex) {
  const tokens = inputString.split(',');
  let tokenValue;

  // Validate token index exists
  if (tokenIndex < tokens.length) {
    tokenValue = tokens[tokenIndex];
  } else {
    // Log the attempted access for debugging
    console.log('Attempting to read token:', tokens[tokenIndex]);
    tokenValue = null;
  }

  return {
    token: tokenValue,
    index: tokenIndex,
    totalTokens: tokens.length
  };
}`,

  vulnerableLine: `tokenValue = tokens[tokenIndex];`,

  options: [
    {
      code: `if (tokenIndex >= 0 && tokenIndex < tokens.length) { tokenValue = tokens[tokenIndex]; } else { tokenValue = null; }`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    {
      code: `tokenValue = tokens[tokenIndex];`,
      correct: false,
      explanation: 'MITRE missing minimum bounds pattern: Only validates upper bound, allows negative indices. Negative tokenIndex values can access unintended array elements or undefined memory, potentially exposing sensitive data.'
    },
    {
      code: `if (tokenIndex < tokens.length && tokenIndex !== undefined) { tokenValue = tokens[tokenIndex]; }`,
      correct: false,
      explanation: 'Undefined check insufficient for negative values. Negative integers are not undefined, so they pass validation but still cause out-of-bounds reads at negative indices.'
    },
    {
      code: `if (Math.abs(tokenIndex) < tokens.length) { tokenValue = tokens[tokenIndex]; }`,
      correct: false,
      explanation: 'Absolute value check creates incorrect logic. For negative tokenIndex -2 in 5-element array, Math.abs(-2) < 5 is true, but accessing tokens[-2] is still invalid.'
    },
    {
      code: `try { tokenValue = tokens[tokenIndex]; } catch(e) { tokenValue = null; }`,
      correct: false,
      explanation: 'Try-catch cannot prevent vulnerability'
    },
    {
      code: `if (typeof tokenIndex === 'number' && tokenIndex < tokens.length) { tokenValue = tokens[tokenIndex]; }`,
      correct: false,
      explanation: 'Type checking allows negative numbers. Negative values are valid numbers but cause out-of-bounds reads when used as array indices.'
    },
    {
      code: `const safeIndex = Math.max(0, Math.min(tokenIndex, tokens.length - 1)); tokenValue = tokens[safeIndex];`,
      correct: false,
      explanation: 'Index clamping prevents crashes but returns wrong token. Reading different index than requested masks the bounds violation and provides incorrect data.'
    },
    {
      code: `if (tokenIndex && tokenIndex < tokens.length) { tokenValue = tokens[tokenIndex]; }`,
      correct: false,
      explanation: 'Truthy check allows negative values. Negative numbers are truthy, so this validation fails to prevent negative index out-of-bounds reads.'
    },
    {
      code: `if (tokenIndex <= tokens.length) { tokenValue = tokens[tokenIndex]; }`,
      correct: false,
      explanation: 'Off-by-one error: valid indices are [0, tokens.length-1]. Index equal to length is out-of-bounds. Also still allows negative indices which can read invalid memory.'
    },
    {
      code: `if (!isNaN(tokenIndex) && tokenIndex < tokens.length) { tokenValue = tokens[tokenIndex]; }`,
      correct: false,
      explanation: 'NaN check does not validate range. Negative numbers are not NaN but still cause out-of-bounds reads when accessing memory at negative array indices.'
    }
  ]
}