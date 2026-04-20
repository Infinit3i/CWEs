import type { Exercise } from '@/data/exercises'

export const cwe125MessageProcessing: Exercise = {
  cweId: 'CWE-125',
  name: 'Out-of-bounds Read - Network Message Parser',

  vulnerableFunction: `function processNetworkMessage(messageBuffer) {
  const BUFFER_SIZE = 1024;
  const MESSAGE_SIZE = 512;

  // Extract message header
  const messageHeader = parseMessageHeader(messageBuffer);
  const messageLength = messageHeader.msgLength;
  const messageBody = messageHeader.msgBody;

  // Copy message data
  const processedMessage = new Array(MESSAGE_SIZE);
  let index = 0;

  for (index = 0; index < messageLength; index++) {
    processedMessage[index] = messageBody[index];
  }

  processedMessage[index] = '\\0'; // null terminator

  return {
    length: messageLength,
    data: processedMessage.slice(0, index),
    complete: true
  };
}`,

  vulnerableLine: `processedMessage[index] = messageBody[index];`,

  options: [
    {
      code: `if (messageLength <= messageBody.length && messageLength <= MESSAGE_SIZE) { /* copy loop */ } else { throw new Error('Invalid message length'); }`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    {
      code: `processedMessage[index] = messageBody[index];`,
      correct: false,
      explanation: 'MITRE unvalidated message length pattern: msgLength from untrusted source controls loop bounds. If msgLength exceeds actual messageBody size, this reads past buffer end, potentially exposing sensitive memory contents or causing crashes.'
    },
    {
      code: `if (messageLength > 0) { /* copy loop */ }`,
      correct: false,
      explanation: 'Positive check insufficient - missing upper bound validation. Large messageLength values can still cause out-of-bounds reads when accessing messageBody beyond its actual size.'
    },
    {
      code: `try { processedMessage[index] = messageBody[index]; } catch(e) { break; }`,
      correct: false,
      explanation: 'Exception handling after out-of-bounds read is too late. Memory access beyond buffer occurs before exceptions can prevent potential information disclosure or crashes.'
    },
    {
      code: `if (index < MESSAGE_SIZE) { processedMessage[index] = messageBody[index]; }`,
      correct: false,
      explanation: 'Only checking destination bounds misses source validation. This prevents destination overflow but still allows reading beyond messageBody boundaries when messageLength is manipulated.'
    },
    {
      code: `const safeByte = messageBody[index] || 0; processedMessage[index] = safeByte;`,
      correct: false,
      explanation: 'Fallback value does not prevent out-of-bounds read. The access to messageBody[index] occurs before the OR operation, potentially reading invalid memory.'
    },
    {
      code: `if (messageLength <= MESSAGE_SIZE) { /* copy loop */ }`,
      correct: false,
      explanation: 'Destination size check incomplete - missing source buffer validation. This prevents destination overflow but allows reading beyond messageBody when attacker controls msgLength.'
    },
    {
      code: `processedMessage[index] = messageBody[Math.min(index, messageBody.length - 1)];`,
      correct: false,
      explanation: 'Index clamping masks the issue by reading wrong data instead of detecting invalid message length. This provides incorrect results rather than proper validation.'
    },
    {
      code: `if (typeof messageLength === 'number') { /* copy loop */ }`,
      correct: false,
      explanation: 'Type checking allows any numeric value including values larger than buffer size. Large numbers are still valid types but cause out-of-bounds reads.'
    },
    {
      code: `const actualLength = Math.min(messageLength, MESSAGE_SIZE); for (index = 0; index < actualLength; index++)`,
      correct: false,
      explanation: 'Limiting by destination size prevents destination overflow but still allows reading beyond messageBody source buffer when messageLength exceeds actual message size.'
    }
  ]
}