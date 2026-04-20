import type { Exercise } from '@/data/exercises'

export const cwe125ArrayAccess: Exercise = {
  cweId: 'CWE-125',
  name: 'Out-of-bounds Read - Array Value Retrieval',

  vulnerableFunction: `function getValueFromArray(dataArray, arrayLength, index) {
  let retrievedValue;

  // Check if index is within array bounds
  if (index < arrayLength) {
    retrievedValue = dataArray[index];
  } else {
    console.log('Index out of bounds, value is:', dataArray[index]);
    retrievedValue = -1;
  }

  return {
    value: retrievedValue,
    index: index,
    valid: index < arrayLength
  };
}`,

  vulnerableLine: `retrievedValue = dataArray[index];`,

  options: [
    {
      code: `if (index >= 0 && index < arrayLength) { retrievedValue = dataArray[index]; } else { retrievedValue = -1; }`,
      correct: true,
      explanation: `Check both lower and upper bounds`
    },
    {
      code: `retrievedValue = dataArray[index];`,
      correct: false,
      explanation: 'Missing negative index check allows underflow'
    },
    {
      code: `if (index < arrayLength && index !== null) { retrievedValue = dataArray[index]; }`,
      correct: false,
      explanation: 'Null check insufficient for negative values. Negative integers are not null, so they pass this validation but still cause out-of-bounds reads before array boundaries.'
    },
    {
      code: `if (Math.abs(index) < arrayLength) { retrievedValue = dataArray[index]; }`,
      correct: false,
      explanation: 'Absolute value check creates incorrect logic. For negative index -2 in array length 5, Math.abs(-2) < 5 is true, but accessing array[-2] still reads invalid memory.'
    },
    {
      code: `if (typeof index === 'number' && index < arrayLength) { retrievedValue = dataArray[index]; }`,
      correct: false,
      explanation: 'Type checking allows negative numbers. Negative values are valid numbers but cause out-of-bounds reads when used as array indices.'
    },
    {
      code: `try { retrievedValue = dataArray[index]; } catch(e) { retrievedValue = -1; }`,
      correct: false,
      explanation: 'Try-catch cannot prevent vulnerability'
    },
    {
      code: `if (index < arrayLength && !isNaN(index)) { retrievedValue = dataArray[index]; }`,
      correct: false,
      explanation: 'NaN check does not validate range. Negative numbers are not NaN but still cause out-of-bounds reads when accessing memory before array start.'
    },
    {
      code: `const safeIndex = Math.max(0, Math.min(index, arrayLength - 1)); retrievedValue = dataArray[safeIndex];`,
      correct: false,
      explanation: 'Index clamping prevents crashes but returns wrong data. Reading different index than requested masks the bounds violation and provides incorrect results to the caller.'
    },
    {
      code: `if (index <= arrayLength) { retrievedValue = dataArray[index]; }`,
      correct: false,
      explanation: 'Off-by-one error: valid indices are [0, arrayLength-1]. Index equal to arrayLength is out-of-bounds and reads past array end. Also still allows negative indices.'
    },
    {
      code: `if (index && index < arrayLength) { retrievedValue = dataArray[index]; }`,
      correct: false,
      explanation: 'Truthy check allows negative values. Negative numbers are truthy in JavaScript, so this validation fails to prevent negative index out-of-bounds reads.'
    }
  ]
}