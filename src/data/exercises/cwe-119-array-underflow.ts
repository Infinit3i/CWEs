import type { Exercise } from '@/data/exercises'

/**
 * CWE-119 exercise: Array index underflow
 * Based on MITRE demonstrative examples showing negative index vulnerabilities
 */
export const cwe119ArrayUnderflow: Exercise = {
  cweId: 'CWE-119',
  name: 'Memory Buffer Bounds - Array Index Underflow in Data Processing',

  vulnerableFunction: `function getValueFromArray(dataArray, arrayLength, index) {
  let value;

  // Check upper bounds but not lower bounds
  if (index < arrayLength) {
    value = dataArray[index];
    console.log(\`Value at index \${index}: \${value}\`);
  } else {
    console.log('Index out of bounds (too high)');
    value = -1;
  }

  return value;
}

function processDataRange(dataArray, startIndex, endIndex) {
  const results = [];

  // Process range of indices
  for (let i = startIndex; i <= endIndex; i++) {
    const value = getValueFromArray(dataArray, dataArray.length, i);
    if (value !== undefined && value !== -1) {
      results.push(value);
    }
  }

  return results;
}

// Example vulnerable call:
// processDataRange([10, 20, 30, 40], -2, 1)
// This would try to access dataArray[-2], dataArray[-1], dataArray[0], dataArray[1]`,

  vulnerableLine: `if (index < arrayLength) {`,

  options: [
    {
      code: `function getValueFromArray(dataArray, arrayLength, index) {
  // Check both upper and lower bounds
  if (index < 0) {
    throw new Error('Negative index not allowed');
  }

  if (index >= arrayLength) {
    throw new Error('Index exceeds array length');
  }

  // Safe access with validated bounds
  return dataArray[index];
}

function processDataRange(dataArray, startIndex, endIndex) {
  if (startIndex < 0 || endIndex < 0) {
    throw new Error('Negative indices not allowed');
  }

  if (startIndex > endIndex) {
    throw new Error('Invalid range: start > end');
  }

  const results = [];
  for (let i = startIndex; i <= endIndex; i++) {
    try {
      const value = getValueFromArray(dataArray, dataArray.length, i);
      results.push(value);
    } catch (e) {
      break; // Stop on first invalid index
    }
  }

  return results;
}`,
      correct: true,
      explanation: `Correct! Comprehensive bounds checking validates both negative indices and upper bounds. This prevents reading before array boundaries, following MITRE recommendations for complete index validation.`
    },
    // Array underflow vulnerabilities from MITRE
    {
      code: `if (index < arrayLength) {
    value = dataArray[index]; // Missing negative index check
}`,
      correct: false,
      explanation: 'Direct from MITRE: Missing lower bounds check allows negative index access. Negative indices can read memory before the array, potentially exposing sensitive data or causing crashes.'
    },
    {
      code: `if (index >= 0 && index <= arrayLength) {
    value = dataArray[index];
}`,
      correct: false,
      explanation: 'Off-by-one error in upper bounds check. Using <= instead of < allows access to index arrayLength, which is beyond the valid array bounds.'
    },
    {
      code: `const safeIndex = Math.abs(index);
if (safeIndex < arrayLength) {
    value = dataArray[safeIndex];
}`,
      correct: false,
      explanation: 'Absolute value conversion can create incorrect behavior. Negative indices might represent valid reverse indexing logic that gets corrupted by forced positive conversion.'
    },
    {
      code: `if (index > -1 && index < arrayLength) {
    value = dataArray[index];
}`,
      correct: false,
      explanation: 'While this correctly checks bounds, using > -1 is less clear than >= 0. The logic is correct but the comparison style can lead to maintenance errors.'
    },
    {
      code: `if (index !== null && index < arrayLength) {
    value = dataArray[index];
}`,
      correct: false,
      explanation: 'Null checking does not prevent negative index access. The condition allows negative numbers to pass through and access memory before the array.'
    },
    {
      code: `try {
    if (index < arrayLength) {
        value = dataArray[index];
    }
} catch (e) {
    value = null;
}`,
      correct: false,
      explanation: 'JavaScript arrays allow negative indices without throwing exceptions. They either return undefined or access Array.prototype properties, so try-catch will not detect underflow.'
    },
    {
      code: `if (typeof index === 'number' && index < arrayLength) {
    value = dataArray[index];
}`,
      correct: false,
      explanation: 'Type checking without bounds validation still allows negative numbers. The condition validates type but not the actual index range safety.'
    },
    {
      code: `const clampedIndex = Math.max(0, Math.min(index, arrayLength - 1));
value = dataArray[clampedIndex];`,
      correct: false,
      explanation: 'Silent clamping can hide programming errors and create unexpected behavior. Applications may not realize indices are being modified, leading to incorrect results.'
    },
    {
      code: `if (index.toString().indexOf('-') === -1 && index < arrayLength) {
    value = dataArray[index];
}`,
      correct: false,
      explanation: 'String-based negative detection is unreliable and inefficient. This approach fails for negative numbers in scientific notation or with different formatting.'
    },
    {
      code: `if (index % 1 === 0 && index < arrayLength) {
    value = dataArray[index];
}`,
      correct: false,
      explanation: 'Integer checking without sign validation allows negative integers. The modulo check ensures whole numbers but does not prevent negative array access.'
    }
  ]
}