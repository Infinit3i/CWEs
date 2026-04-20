import type { Exercise } from '@/data/exercises'

export const cwe787BufferWrite: Exercise = {
  cweId: 'CWE-787',
  name: 'Out-of-bounds Write - User Message Processing',

  vulnerableFunction: `function processUserMessage(message) {
  const buffer = new Array(64);
  let index = 0;

  // Copy message characters to buffer
  for (let i = 0; i < message.length; i++) {
    buffer[index] = message.charCodeAt(i);
    index++;
  }

  return buffer.slice(0, index);
}`,

  vulnerableLine: `buffer[index] = message.charCodeAt(i);`,

  options: [
    {
      code: `if (index < buffer.length) { buffer[index] = message.charCodeAt(i); index++; }`,
      correct: true,
      explanation: `Correct! This bounds check ensures we never write past the allocated buffer size. The write only occurs when index is within the valid range [0, buffer.length-1], preventing out-of-bounds writes that could corrupt memory or crash the application.`
    },
    {
      code: `buffer[index] = message.charCodeAt(i); index++;`,
      correct: false,
      explanation: 'Direct from MITRE pattern: Writing to array without bounds checking. When message length exceeds 64 characters, this writes beyond the allocated buffer, potentially overwriting adjacent memory structures.'
    },
    {
      code: `buffer[index % buffer.length] = message.charCodeAt(i); index++;`,
      correct: false,
      explanation: 'Modulo operation prevents crashes but causes data corruption by overwriting earlier buffer contents. This silently truncates data and can lead to unpredictable behavior.'
    },
    {
      code: `try { buffer[index] = message.charCodeAt(i); index++; } catch(e) { /* ignore */ }`,
      correct: false,
      explanation: 'Exception handling after the fact does not prevent the out-of-bounds write. The memory corruption occurs before the exception is thrown.'
    },
    {
      code: `buffer[Math.min(index, buffer.length-1)] = message.charCodeAt(i); index++;`,
      correct: false,
      explanation: 'This prevents out-of-bounds writes but overwrites the last buffer element repeatedly, losing data and creating incorrect output.'
    },
    {
      code: `if (message.length <= 64) { buffer[index] = message.charCodeAt(i); index++; }`,
      correct: false,
      explanation: 'Checking total message length once is insufficient. The vulnerability occurs during iteration - need per-iteration bounds checking.'
    },
    {
      code: `buffer.push(message.charCodeAt(i));`,
      correct: false,
      explanation: 'While push() prevents out-of-bounds writes, this changes the buffer from fixed-size Array(64) to dynamic array, breaking the intended memory layout.'
    },
    {
      code: `buffer[index] = message.charCodeAt(i) || 0; index++;`,
      correct: false,
      explanation: 'The logical OR operator does not prevent out-of-bounds writes. This still writes past buffer boundaries when index exceeds buffer length.'
    },
    {
      code: `if (index >= 0) { buffer[index] = message.charCodeAt(i); index++; }`,
      correct: false,
      explanation: 'Checking for negative index misses the critical upper bound. This still allows writes beyond buffer.length, causing memory corruption.'
    },
    {
      code: `buffer[index] = message.length > 64 ? 0 : message.charCodeAt(i); index++;`,
      correct: false,
      explanation: 'Conditional value assignment does not prevent the out-of-bounds write itself. The buffer access still occurs at invalid indices.'
    }
  ]
}