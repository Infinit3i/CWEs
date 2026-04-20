import type { Exercise } from '@/data/exercises'

export const cwe125ArrayAccess: Exercise = {
  cweId: 'CWE-125',
  name: 'Out-of-bounds Read - Array Value Retrieval',
  language: 'C',

  vulnerableFunction: `#include <stdio.h>

typedef struct {
    int value;
    int index;
    int valid;
} ArrayResult;

ArrayResult get_value_from_array(int* data_array, int array_length, int index) {
    ArrayResult result;
    int retrieved_value;

    // Check if index is within array bounds
    if (index < array_length) {
        retrieved_value = data_array[index];
        result.valid = 1;
    } else {
        // VULNERABLE: Still reads out-of-bounds value for logging
        printf("Index out of bounds, value is: %d\\n", data_array[index]);
        retrieved_value = -1;
        result.valid = 0;
    }

    result.value = retrieved_value;
    result.index = index;

    return result;
}`,

  vulnerableLine: `printf("Index out of bounds, value is: %d\\n", data_array[index]);`,

  options: [
    {
      code: `ArrayResult get_value_from_array(int* data_array, int array_length, int index) {
    ArrayResult result;

    // Proper bounds checking for both upper and lower bounds
    if (index >= 0 && index < array_length) {
        result.value = data_array[index];
        result.valid = 1;
    } else {
        printf("Index %d out of bounds for array of size %d\\n", index, array_length);
        result.value = -1;
        result.valid = 0;
    }

    result.index = index;
    return result;
}`,
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