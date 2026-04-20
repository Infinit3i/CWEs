import type { Exercise } from '@/data/exercises'

/**
 * CWE-190 exercise: Loop counter overflow
 * Based on MITRE demonstrative examples showing loop overflow vulnerabilities
 */
export const cwe190LoopCounter: Exercise = {
  cweId: 'CWE-190',
  name: 'Integer Overflow - Network Packet Processing Loop',
  language: 'C++',

  vulnerableFunction: `function processNetworkPackets(packetData) {
  let bytesProcessed = 0; // Using 16-bit integer (max 65535)
  const buffer = new ArrayBuffer(65536);
  const view = new Uint8Array(buffer);

  while (bytesProcessed < packetData.length) {
    const chunkSize = Math.min(1024, packetData.length - bytesProcessed);

    // Process chunk
    for (let i = 0; i < chunkSize; i++) {
      view[bytesProcessed + i] = packetData[bytesProcessed + i];
    }

    bytesProcessed += chunkSize;

    // Log progress
    console.log(\`Processed \${bytesProcessed} bytes\`);
  }

  return view.slice(0, bytesProcessed);
}`,

  vulnerableLine: `bytesProcessed += chunkSize;`,

  options: [
    {
      code: `function processNetworkPackets(packetData) {
  let bytesProcessed = 0;
  const MAX_SAFE_BYTES = Number.MAX_SAFE_INTEGER;

  while (bytesProcessed < packetData.length && bytesProcessed < MAX_SAFE_BYTES) {
    const chunkSize = Math.min(1024, packetData.length - bytesProcessed);

    if (bytesProcessed > MAX_SAFE_BYTES - chunkSize) {
      throw new Error('Processing would overflow counter');
    }

    processChunk(bytesProcessed, chunkSize);
    bytesProcessed += chunkSize;
  }
  return bytesProcessed;
}`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    // Loop counter overflow vulnerabilities from MITRE
    {
      code: `let bytesProcessed = 0; // 16-bit counter
while (bytesProcessed < packetData.length) {
    bytesProcessed += chunkSize; // Can overflow and wrap to negative/small value
}`,
      correct: false,
      explanation: 'Loop counter overflow can wrap bytesProcessed to a negative or small value, creating infinite loops and buffer overflows when used as array indices.'
    },
    {
      code: `for (let count = 0; count < targetCount; count++) {
    processItem(count);
    if (count % 1000 === 0) count += bonusIncrement;
}`,
      correct: false,
      explanation: 'MITRE-style loop manipulation with additional increments. The counter can overflow, wrapping to small values and creating infinite loops.'
    },
    {
      code: `let processed = 0;
while (processed >= 0 && processed < dataSize) {
    processed += getNextChunkSize();
}`,
      correct: false,
      explanation: 'Checking for negative values after increment is insufficient. Integer overflow can wrap to small positive values, bypassing the negative check.'
    },
    {
      code: `let byteCounter = 0;
do {
    byteCounter += processNextPacket();
} while (byteCounter <= maxBytes && byteCounter != 0);`,
      correct: false,
      explanation: 'Zero-checking misses the overflow scenario. Counter can wrap to small positive values, continuing the loop beyond intended bounds.'
    },
    {
      code: `for (let i = startPos; i < endPos; i += stepSize) {
    if (i < startPos) break; // Overflow check
    processPosition(i);
}`,
      correct: false,
      explanation: 'Post-increment overflow detection is too late. The loop variable has already overflowed, and array access may have occurred with the wrapped value.'
    },
    {
      code: `let accumulator = 0;
while (accumulator < threshold) {
    accumulator = (accumulator + increment) % Number.MAX_VALUE;
}`,
      correct: false,
      explanation: 'Modulo operation prevents overflow but changes program logic. The accumulator may never reach the threshold, creating infinite loops.'
    },
    {
      code: `let counter = 0;
while (counter.toString().length < 10) {
    counter += largeIncrement;
}`,
      correct: false,
      explanation: 'String length checking as overflow detection is unreliable. Overflowed values may wrap to small numbers with short string representations.'
    },
    {
      code: `let position = 0;
while (position < dataLength) {
    position = Math.abs(position + chunkSize);
}`,
      correct: false,
      explanation: 'Absolute value cannot fix overflow. If position + chunkSize overflows to a large negative value, Math.abs makes it positive but potentially huge.'
    },
    {
      code: `let bytesRead = 0;
try {
    while (bytesRead < fileSize) {
        bytesRead += readBuffer.length;
    }
} catch (overflow) {
    console.log('Overflow detected');
}`,
      correct: false,
      explanation: 'JavaScript integer overflow does not throw exceptions. The try-catch will not detect overflow conditions, and the loop can still become infinite.'
    }
  ]
}