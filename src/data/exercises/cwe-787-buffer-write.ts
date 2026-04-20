import type { Exercise } from '@/data/exercises'

export const cwe787BufferWrite: Exercise = {
  cweId: 'CWE-787',
  name: 'Out-of-bounds Write - User Message Processing',
  language: 'C',

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
      explanation: `Check bounds before writing to arrays`
    },
    {
      code: `buffer[index] = message.charCodeAt(i); index++;`,
      correct: false,
      explanation: 'No bounds check allows buffer overflow'
    },
    {
      code: `buffer[index % buffer.length] = message.charCodeAt(i); index++;`,
      correct: false,
      explanation: 'Modulo overwrites existing data causing corruption'
    },
    {
      code: `try { buffer[index] = message.charCodeAt(i); index++; } catch(e) { /* ignore */ }`,
      correct: false,
      explanation: 'Try-catch cannot prevent buffer overflow damage'
    },
    {
      code: `buffer[Math.min(index, buffer.length-1)] = message.charCodeAt(i); index++;`,
      correct: false,
      explanation: 'Overwrites last element repeatedly, losing data'
    },
    {
      code: `if (message.length <= 64) { buffer[index] = message.charCodeAt(i); index++; }`,
      correct: false,
      explanation: 'Check bounds every iteration, not once'
    },
    {
      code: `buffer.push(message.charCodeAt(i));`,
      correct: false,
      explanation: 'Push() changes fixed-size to dynamic array'
    },
    {
      code: `buffer[index] = message.charCodeAt(i) || 0; index++;`,
      correct: false,
      explanation: 'Logical OR does not prevent overflow'
    },
    {
      code: `if (index >= 0) { buffer[index] = message.charCodeAt(i); index++; }`,
      correct: false,
      explanation: 'Missing upper bound check allows overflow'
    },
    {
      code: `buffer[index] = message.length > 64 ? 0 : message.charCodeAt(i); index++;`,
      correct: false,
      explanation: 'Still writes to invalid buffer indices'
    }
  ]
}