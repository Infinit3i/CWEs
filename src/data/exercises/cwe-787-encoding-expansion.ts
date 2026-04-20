import type { Exercise } from '@/data/exercises'

export const cwe787EncodingExpansion: Exercise = {
  cweId: 'CWE-787',
  name: 'Out-of-bounds Write - HTML Encoding Buffer',

  vulnerableFunction: `function encodeHTMLEntities(userInput) {
  // Allocate 4x buffer assuming worst case encoding
  const maxSize = userInput.length;
  const encodedBuffer = new Array(4 * maxSize);
  let writeIndex = 0;

  for (let i = 0; i < userInput.length; i++) {
    const char = userInput[i];
    if (char === '&') {
      // Encode ampersand as &amp; (5 characters)
      encodedBuffer[writeIndex++] = '&'.charCodeAt(0);
      encodedBuffer[writeIndex++] = 'a'.charCodeAt(0);
      encodedBuffer[writeIndex++] = 'm'.charCodeAt(0);
      encodedBuffer[writeIndex++] = 'p'.charCodeAt(0);
      encodedBuffer[writeIndex++] = ';'.charCodeAt(0);
    } else {
      encodedBuffer[writeIndex++] = char.charCodeAt(0);
    }
  }

  return encodedBuffer.slice(0, writeIndex);
}`,

  vulnerableLine: `encodedBuffer[writeIndex++] = ';'.charCodeAt(0);`,

  options: [
    {
      code: `const encodedBuffer = new Array(5 * maxSize);`,
      correct: true,
      explanation: `Correct! Allocating 5x buffer size accounts for the worst case where every character is an ampersand requiring 5-character encoding (&amp;). This prevents buffer overflow when multiple ampersands are encoded to their 5-character HTML entity representation.`
    },
    {
      code: `const encodedBuffer = new Array(4 * maxSize);`,
      correct: false,
      explanation: 'MITRE encoding expansion pattern: Buffer allocated assuming 4x expansion but &amp; requires 5 characters. Multiple ampersands cause writes beyond allocated buffer, corrupting memory.'
    },
    {
      code: `if (writeIndex < encodedBuffer.length - 5) { /* encoding logic */ }`,
      correct: false,
      explanation: 'While this prevents some overflows, it fails to handle the case where buffer is nearly full and abandons encoding, potentially producing incomplete or invalid HTML.'
    },
    {
      code: `const encodedBuffer = new Array(userInput.length + 50);`,
      correct: false,
      explanation: 'Fixed padding insufficient for all cases. Input with many ampersands can still exceed buffer bounds since &amp; requires 4 additional characters per ampersand.'
    },
    {
      code: `try { encodedBuffer[writeIndex++] = ';'.charCodeAt(0); } catch(e) { return encodedBuffer.slice(0, writeIndex-1); }`,
      correct: false,
      explanation: 'Exception handling after buffer overflow is too late. Memory corruption occurs before exception handling can prevent it.'
    },
    {
      code: `encodedBuffer[writeIndex % encodedBuffer.length] = ';'.charCodeAt(0); writeIndex++;`,
      correct: false,
      explanation: 'Modulo prevents crashes but causes data corruption by wrapping around and overwriting earlier encoded content, producing invalid HTML entities.'
    },
    {
      code: `if (writeIndex < encodedBuffer.length) { encodedBuffer[writeIndex++] = ';'.charCodeAt(0); }`,
      correct: false,
      explanation: 'Bounds check prevents crashes but silently truncates encoding mid-entity, creating malformed HTML like "&amp" instead of "&amp;", breaking HTML parsing.'
    },
    {
      code: `const encodedBuffer = []; /* use push() instead */`,
      correct: false,
      explanation: 'Dynamic array avoids overflow but defeats the purpose of pre-allocated fixed-size buffer, changing performance characteristics and memory usage patterns.'
    },
    {
      code: `const encodedBuffer = new Array(Math.max(4 * maxSize, 1000));`,
      correct: false,
      explanation: 'Minimum buffer size does not solve fundamental miscalculation. For inputs with many ampersands, 4x expansion is still insufficient regardless of minimum size.'
    },
    {
      code: `encodedBuffer.length = Math.max(encodedBuffer.length, writeIndex + 1);`,
      correct: false,
      explanation: 'Dynamically resizing after allocation is inefficient and may not guarantee contiguous memory. Original buffer size calculation should be correct from the start.'
    }
  ]
}