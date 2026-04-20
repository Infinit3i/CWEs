import type { Exercise } from '@/data/exercises'

/**
 * CWE-119 exercise: Encoding expansion buffer overflow
 * Based on MITRE demonstrative examples showing encoding expansion vulnerabilities
 */
export const cwe119EncodingExpansion: Exercise = {
  cweId: 'CWE-119',
  name: 'Memory Buffer Bounds - HTML Entity Encoding Expansion',

  vulnerableFunction: `// Simulated C-style function for HTML entity encoding
function encodeHTMLEntities(userInput) {
  const MAX_INPUT_SIZE = 1000;

  // Validate input size
  if (userInput.length > MAX_INPUT_SIZE) {
    throw new Error('Input too long');
  }

  // Allocate buffer assuming 4x expansion (insufficient for HTML entities)
  const outputBuffer = new Array(MAX_INPUT_SIZE * 4);
  let bufferIndex = 0;

  for (let i = 0; i < userInput.length; i++) {
    const char = userInput[i];

    switch (char) {
      case '&':
        // HTML entity: &amp; (5 characters)
        outputBuffer[bufferIndex++] = '&';
        outputBuffer[bufferIndex++] = 'a';
        outputBuffer[bufferIndex++] = 'm';
        outputBuffer[bufferIndex++] = 'p';
        outputBuffer[bufferIndex++] = ';';
        break;
      case '<':
        // HTML entity: &lt; (4 characters)
        outputBuffer[bufferIndex++] = '&';
        outputBuffer[bufferIndex++] = 'l';
        outputBuffer[bufferIndex++] = 't';
        outputBuffer[bufferIndex++] = ';';
        break;
      case '"':
        // HTML entity: &quot; (6 characters)
        outputBuffer[bufferIndex++] = '&';
        outputBuffer[bufferIndex++] = 'q';
        outputBuffer[bufferIndex++] = 'u';
        outputBuffer[bufferIndex++] = 'o';
        outputBuffer[bufferIndex++] = 't';
        outputBuffer[bufferIndex++] = ';';
        break;
      default:
        outputBuffer[bufferIndex++] = char;
        break;
    }
  }

  return outputBuffer.slice(0, bufferIndex).join('');
}

// Example: String with many ampersands could overflow
// encodeHTMLEntities('&'.repeat(1000)) // 1000 * 5 = 5000 characters needed`,

  vulnerableLine: `outputBuffer[bufferIndex++] = '&';`,

  options: [
    {
      code: `function encodeHTMLEntities(userInput) {
  const MAX_INPUT_SIZE = 1000;
  const MAX_EXPANSION_RATIO = 6; // &quot; is longest at 6 chars

  if (userInput.length > MAX_INPUT_SIZE) {
    throw new Error('Input too long');
  }

  // Calculate maximum possible output size
  const maxOutputSize = userInput.length * MAX_EXPANSION_RATIO;
  const outputBuffer = new Array(maxOutputSize);
  let bufferIndex = 0;

  for (let i = 0; i < userInput.length; i++) {
    const char = userInput[i];

    // Always check buffer bounds before writing
    if (bufferIndex + 6 >= maxOutputSize) {
      throw new Error('Output buffer would overflow');
    }

    switch (char) {
      case '&':
        outputBuffer[bufferIndex++] = '&';
        outputBuffer[bufferIndex++] = 'a';
        outputBuffer[bufferIndex++] = 'm';
        outputBuffer[bufferIndex++] = 'p';
        outputBuffer[bufferIndex++] = ';';
        break;
      // ... other cases
      default:
        outputBuffer[bufferIndex++] = char;
        break;
    }
  }

  return outputBuffer.slice(0, bufferIndex).join('');
}`,
      correct: true,
      explanation: `Correct! Proper expansion ratio calculation and bounds checking prevents overflow. The buffer is sized for maximum possible expansion, and each write operation is bounds-checked before execution.`
    },
    // Encoding expansion vulnerabilities from MITRE
    {
      code: `const outputBuffer = new Array(MAX_INPUT_SIZE * 4);
for (let i = 0; i < userInput.length; i++) {
    // Encode entities without checking if buffer can hold expansion
    outputBuffer[bufferIndex++] = '&';
    outputBuffer[bufferIndex++] = 'a';
    outputBuffer[bufferIndex++] = 'm';
    outputBuffer[bufferIndex++] = 'p';
    outputBuffer[bufferIndex++] = ';';
}`,
      correct: false,
      explanation: 'Direct from MITRE: Insufficient expansion buffer with HTML entities. 4x expansion is inadequate - strings with many ampersands need 5x expansion, causing buffer overflow.'
    },
    {
      code: `const outputBuffer = new Array(userInput.length * 2);
for (const char of userInput) {
    if (char === '&') {
        // &amp; requires 5 characters
        outputBuffer[bufferIndex++] = '&';
        outputBuffer[bufferIndex++] = 'a';
        outputBuffer[bufferIndex++] = 'm';
        outputBuffer[bufferIndex++] = 'p';
        outputBuffer[bufferIndex++] = ';';
    }
}`,
      correct: false,
      explanation: 'Severe under-allocation with only 2x expansion. HTML entities like &quot; (6 chars) and &amp; (5 chars) far exceed the 2x ratio, guaranteed to overflow.'
    },
    {
      code: `// Check available space after encoding each character
if (bufferIndex < outputBuffer.length - 1) {
    outputBuffer[bufferIndex++] = '&';
    outputBuffer[bufferIndex++] = 'a'; // No check for remaining chars
    outputBuffer[bufferIndex++] = 'm';
    outputBuffer[bufferIndex++] = 'p';
    outputBuffer[bufferIndex++] = ';';
}`,
      correct: false,
      explanation: 'Partial bounds checking only validates first character of entity. The remaining 4 characters of &amp; are written without bounds checking, causing overflow.'
    },
    {
      code: `const outputBuffer = new Array(MAX_INPUT_SIZE * 3);
// Encode without expansion awareness
for (let i = 0; i < userInput.length; i++) {
    if (userInput[i] === '"') {
        // &quot; is 6 characters but only allocated 3x space
        const entity = '&quot;';
        for (let j = 0; j < entity.length; j++) {
            outputBuffer[bufferIndex++] = entity[j];
        }
    }
}`,
      correct: false,
      explanation: '3x expansion insufficient for HTML entities. &quot; requires 6 characters per input character, but 3x allocation only provides 3 characters, causing overflow.'
    },
    {
      code: `let result = '';
for (const char of userInput) {
    if (char === '&') result += '&amp;';
    else result += char;
}
// Then copy to fixed buffer
const buffer = new Array(MAX_INPUT_SIZE);
for (let i = 0; i < result.length; i++) {
    buffer[i] = result[i];
}`,
      correct: false,
      explanation: 'Safe dynamic string building followed by unsafe fixed buffer copy. The expanded result can exceed the fixed buffer size during the copy operation.'
    },
    {
      code: `const outputBuffer = new Array(userInput.length * 8); // Over-allocated
for (let i = 0; i < userInput.length; i++) {
    // But still no bounds checking during write
    outputBuffer[bufferIndex++] = '&';
    outputBuffer[bufferIndex++] = 'q';
    outputBuffer[bufferIndex++] = 'u';
    outputBuffer[bufferIndex++] = 'o';
    outputBuffer[bufferIndex++] = 't';
    outputBuffer[bufferIndex++] = ';';
}`,
      correct: false,
      explanation: 'Large allocation without runtime bounds checking. While 8x may be sufficient, lack of bounds checking means buffer overflows are still possible with edge cases or bugs.'
    },
    {
      code: `if (userInput.includes('&') && userInput.length > 800) {
    throw new Error('Input likely to cause overflow');
}
const outputBuffer = new Array(MAX_INPUT_SIZE * 4);
// Proceed with encoding without per-character checking`,
      correct: false,
      explanation: 'Heuristic overflow detection is unreliable. Many smaller ampersands or other entities can still cause overflow without triggering this coarse-grained check.'
    },
    {
      code: `const outputBuffer = new Array(MAX_INPUT_SIZE * 4);
let estimatedSize = 0;
for (const char of userInput) {
    if (char === '&') estimatedSize += 5;
    else estimatedSize += 1;
}
// Check estimate but still encode unsafely
if (estimatedSize > outputBuffer.length) throw new Error('Would overflow');`,
      correct: false,
      explanation: 'Pre-calculation without runtime bounds checking. The estimate may be correct, but the actual encoding loop still lacks bounds checking, risking overflow from implementation bugs.'
    },
    {
      code: `try {
    for (const char of userInput) {
        if (char === '&') {
            outputBuffer[bufferIndex++] = '&';
            outputBuffer[bufferIndex++] = 'a';
            outputBuffer[bufferIndex++] = 'm';
            outputBuffer[bufferIndex++] = 'p';
            outputBuffer[bufferIndex++] = ';';
        }
    }
} catch (e) {
    return 'Encoding failed';
}`,
      correct: false,
      explanation: 'JavaScript arrays automatically expand rather than throwing exceptions on out-of-bounds access. Try-catch will not detect buffer overflow conditions.'
    },
    {
      code: `const chunkSize = Math.floor(outputBuffer.length / userInput.length);
for (let i = 0; i < userInput.length; i++) {
    const startPos = i * chunkSize;
    if (userInput[i] === '&') {
        // Fixed allocation per character regardless of actual needs
        outputBuffer[startPos] = '&';
        outputBuffer[startPos + 1] = 'a';
        outputBuffer[startPos + 2] = 'm';
        outputBuffer[startPos + 3] = 'p';
        outputBuffer[startPos + 4] = ';';
    }
}`,
      correct: false,
      explanation: 'Fixed chunking wastes buffer space and may under-allocate. If chunkSize < 6, entities like &quot; cannot fit, causing overlap or corruption between chunks.'
    }
  ]
}