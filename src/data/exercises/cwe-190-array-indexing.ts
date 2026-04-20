import type { Exercise } from '@/data/exercises'

/**
 * CWE-190 exercise: Array indexing overflow
 * Based on buffer indexing vulnerabilities from MITRE examples
 */
export const cwe190ArrayIndexing: Exercise = {
  cweId: 'CWE-190',
  name: 'Integer Overflow - Array Indexing in Data Processing',

  vulnerableFunction: `function processDataChunks(dataArray, startIndex, chunkSize) {
  const results = [];

  for (let i = 0; i < dataArray.length; i += chunkSize) {
    const currentIndex = startIndex + i;

    // Process current chunk
    if (currentIndex < dataArray.length) {
      const chunk = dataArray.slice(currentIndex, currentIndex + chunkSize);
      results.push(processChunk(chunk));
    }

    // Update progress tracking
    updateProgress(currentIndex, dataArray.length);
  }

  return results;
}

function updateProgress(current, total) {
  const percentage = (current * 100) / total;
  console.log(\`Progress: \${Math.floor(percentage)}%\`);
}`,

  vulnerableLine: `const currentIndex = startIndex + i;`,

  options: [
    {
      code: `function processDataChunks(dataArray, startIndex, chunkSize) {
  if (startIndex < 0 || startIndex >= dataArray.length) {
    throw new Error('Invalid start index');
  }

  const results = [];
  for (let i = 0; i < dataArray.length; i += chunkSize) {
    if (startIndex > Number.MAX_SAFE_INTEGER - i) {
      throw new Error('Index calculation would overflow');
    }
    const currentIndex = startIndex + i;
    if (currentIndex < dataArray.length) {
      results.push(processChunk(dataArray.slice(currentIndex, currentIndex + chunkSize)));
    }
  }
  return results;
}`,
      correct: true,
      explanation: `Correct! Pre-addition overflow checking prevents index calculations from wrapping around. This ensures array access remains within valid bounds and prevents buffer overread vulnerabilities.`
    },
    // Array indexing overflow vulnerabilities
    {
      code: `const currentIndex = startIndex + i;
if (currentIndex < dataArray.length) {
    const chunk = dataArray.slice(currentIndex, currentIndex + chunkSize);
}`,
      correct: false,
      explanation: 'Index calculation without overflow protection. Large startIndex + i can wrap to negative values, accessing memory before the array bounds or wrapping to small positive indices.'
    },
    {
      code: `for (let pos = startPos; pos < endPos; pos += step) {
    dataBuffer[pos] = processValue(inputData[pos]);
}`,
      correct: false,
      explanation: 'MITRE-style loop with potential index overflow. If pos + step overflows, pos can wrap to a small value, creating infinite loops and buffer overflow conditions.'
    },
    {
      code: `const nextIndex = (currentIndex + offset) % arrayLength;
return dataArray[nextIndex];`,
      correct: false,
      explanation: 'Modulo operation changes program semantics. While it prevents true overflow, it creates wraparound indexing that may access unintended data.'
    },
    {
      code: `if (baseIndex + increment > 0) {
    return dataArray[baseIndex + increment];
}`,
      correct: false,
      explanation: 'Checking positivity after addition misses overflow cases. Large positive additions can wrap to negative values, bypassing this check.'
    },
    {
      code: `const safeIndex = Math.min(startIndex + i, dataArray.length - 1);
return dataArray[safeIndex];`,
      correct: false,
      explanation: 'Clamping index after overflow has occurred. The addition may have already wrapped around before the Math.min constraint is applied.'
    },
    {
      code: `try {
    const index = computeIndex(base, offset);
    return dataArray[index];
} catch (e) {
    return dataArray[0]; // Fallback to first element
}`,
      correct: false,
      explanation: 'JavaScript integer overflow does not throw exceptions. Array access with overflowed indices will not trigger catch blocks.'
    },
    {
      code: `const index = (startIndex + i) & 0x7FFFFFFF;
if (index < dataArray.length) {
    return dataArray[index];
}`,
      correct: false,
      explanation: 'Bit masking to force positive values can create incorrect indices. The masked result may not represent the intended array position.'
    },
    {
      code: `if (String(startIndex + i).length < 10) {
    return dataArray[startIndex + i];
}`,
      correct: false,
      explanation: 'String length checking as overflow detection is unreliable. Overflowed values can wrap to small numbers with short string representations.'
    },
    {
      code: `const computedIndex = parseInt((startIndex + i).toString());
return dataArray[Math.abs(computedIndex)];`,
      correct: false,
      explanation: 'String conversion and absolute value cannot fix overflow. Overflowed negative values made positive can still point to invalid array positions.'
    }
  ]
}