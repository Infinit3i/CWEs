import type { Exercise } from '@/data/exercises'

export const cwe125BufferReader: Exercise = {
  cweId: 'CWE-125',
  name: 'Out-of-bounds Read - Binary Data Reader',
  language: 'C',

  vulnerableFunction: `function readBinaryData(dataBuffer, startOffset, readLength) {
  const result = [];

  // Validate read parameters
  if (startOffset < dataBuffer.length && readLength > 0) {
    // Read specified number of bytes
    for (let i = 0; i < readLength; i++) {
      const byteValue = dataBuffer[startOffset + i];
      result.push(byteValue);
    }
  }

  return {
    data: result,
    offset: startOffset,
    length: readLength,
    success: result.length === readLength
  };
}`,

  vulnerableLine: `const byteValue = dataBuffer[startOffset + i];`,

  options: [
    {
      code: `if (startOffset >= 0 && startOffset + readLength <= dataBuffer.length) { /* read loop */ } else { throw new Error('Invalid read parameters'); }`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    {
      code: `const byteValue = dataBuffer[startOffset + i];`,
      correct: false,
      explanation: 'MITRE insufficient bounds validation: Only checks startOffset < length, missing negative offset check and end boundary validation. Negative startOffset or startOffset + readLength exceeding buffer size causes out-of-bounds reads.'
    },
    {
      code: `if (startOffset + i < dataBuffer.length) { const byteValue = dataBuffer[startOffset + i]; }`,
      correct: false,
      explanation: 'Per-iteration bounds checking inefficient and incomplete. Still allows negative startOffset values and should validate total read range upfront rather than each iteration.'
    },
    {
      code: `try { const byteValue = dataBuffer[startOffset + i]; result.push(byteValue); } catch(e) { break; }`,
      correct: false,
      explanation: 'Exception handling after out-of-bounds read is too late. Memory access beyond buffer occurs before exceptions can prevent potential data exposure or crashes.'
    },
    {
      code: `if (typeof startOffset === 'number' && startOffset < dataBuffer.length) { /* read loop */ }`,
      correct: false,
      explanation: 'Type and upper bound checks insufficient. Negative numbers are valid types and startOffset < length check allows negative values that cause underflow reads.'
    },
    {
      code: `const endOffset = Math.min(startOffset + readLength, dataBuffer.length); for (let i = 0; i < endOffset - startOffset; i++)`,
      correct: false,
      explanation: 'Clamping end offset prevents some overflows but allows negative startOffset. Also changes read behavior by returning partial data instead of error for invalid ranges.'
    },
    {
      code: `if (readLength <= dataBuffer.length && startOffset < dataBuffer.length) { /* read loop */ }`,
      correct: false,
      explanation: 'Separate validations miss combined effect. Even if readLength and startOffset are individually valid, startOffset + readLength can exceed buffer bounds.'
    },
    {
      code: `const safeOffset = Math.max(0, startOffset); const safeLength = Math.min(readLength, dataBuffer.length);`,
      correct: false,
      explanation: 'Parameter sanitization masks invalid input instead of rejecting it. Invalid read parameters should trigger errors rather than silent modification of read behavior.'
    },
    {
      code: `if (startOffset >= 0 && readLength > 0) { /* read loop */ }`,
      correct: false,
      explanation: 'Parameter validation incomplete - missing end boundary check. While startOffset >= 0 prevents underflow, startOffset + readLength can still exceed buffer size causing overflow reads.'
    },
    {
      code: `const byteValue = dataBuffer[startOffset + i] || 0;`,
      correct: false,
      explanation: 'Fallback value does not prevent out-of-bounds read. The array access occurs before the OR operation, potentially reading invalid memory before providing fallback.'
    }
  ]
}