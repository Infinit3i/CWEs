import type { Exercise } from '@/data/exercises'

/**
 * CWE-119 exercise: Network packet buffer bounds
 * Based on network packet processing vulnerabilities
 */
export const cwe119PacketProcessing: Exercise = {
  cweId: 'CWE-119',
  name: 'Memory Buffer Bounds - Network Packet Header Processing',

  vulnerableFunction: `function parseNetworkPacket(packetBuffer, expectedSize) {
  const HEADER_SIZE = 20;
  const MAX_PAYLOAD_SIZE = 1024;

  // Validate expected packet size
  if (expectedSize > MAX_PAYLOAD_SIZE + HEADER_SIZE) {
    throw new Error('Packet too large');
  }

  // Allocate buffer for packet processing
  const processedBuffer = new Array(expectedSize);
  let writeIndex = 0;

  // Copy header (assume header is always HEADER_SIZE)
  for (let i = 0; i < HEADER_SIZE; i++) {
    processedBuffer[writeIndex++] = packetBuffer[i];
  }

  // Extract payload length from header (simulated)
  const payloadLength = getPayloadLength(packetBuffer);

  // Copy payload data
  const payloadStart = HEADER_SIZE;
  for (let i = 0; i < payloadLength; i++) {
    const sourceIndex = payloadStart + i;
    if (sourceIndex < packetBuffer.length) {
      processedBuffer[writeIndex++] = packetBuffer[sourceIndex];
    }
  }

  return {
    header: processedBuffer.slice(0, HEADER_SIZE),
    payload: processedBuffer.slice(HEADER_SIZE, writeIndex),
    totalSize: writeIndex
  };
}

function getPayloadLength(buffer) {
  // Simulated payload length extraction from header
  // In real implementation, this could be compromised
  return parseInt(buffer.slice(16, 20).join(''), 10) || 0;
}`,

  vulnerableLine: `for (let i = 0; i < payloadLength; i++) {`,

  options: [
    {
      code: `function parseNetworkPacket(packetBuffer, expectedSize) {
  const HEADER_SIZE = 20;
  const MAX_PAYLOAD_SIZE = 1024;

  if (expectedSize > MAX_PAYLOAD_SIZE + HEADER_SIZE) {
    throw new Error('Packet too large');
  }

  if (packetBuffer.length < HEADER_SIZE) {
    throw new Error('Packet too small for header');
  }

  const processedBuffer = new Array(expectedSize);
  let writeIndex = 0;

  // Safely copy header
  for (let i = 0; i < HEADER_SIZE; i++) {
    processedBuffer[writeIndex++] = packetBuffer[i];
  }

  const payloadLength = getPayloadLength(packetBuffer);

  // Validate payload length against buffer capacity
  if (payloadLength < 0) {
    throw new Error('Invalid payload length');
  }

  if (payloadLength > MAX_PAYLOAD_SIZE) {
    throw new Error('Payload too large');
  }

  if (HEADER_SIZE + payloadLength > packetBuffer.length) {
    throw new Error('Payload length exceeds packet size');
  }

  if (writeIndex + payloadLength > processedBuffer.length) {
    throw new Error('Processed buffer overflow');
  }

  // Safe payload copy with bounds checking
  for (let i = 0; i < payloadLength; i++) {
    processedBuffer[writeIndex++] = packetBuffer[HEADER_SIZE + i];
  }

  return {
    header: processedBuffer.slice(0, HEADER_SIZE),
    payload: processedBuffer.slice(HEADER_SIZE, writeIndex),
    totalSize: writeIndex
  };
}`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    // Network packet processing vulnerabilities
    {
      code: `for (let i = 0; i < payloadLength; i++) {
    const sourceIndex = payloadStart + i;
    processedBuffer[writeIndex++] = packetBuffer[sourceIndex];
}`,
      correct: false,
      explanation: 'Unchecked payload length allows buffer overread. Malformed packets with large payload lengths can read past the packet buffer boundaries, exposing adjacent memory.'
    },
    {
      code: `const payloadLength = getPayloadLength(packetBuffer);
// Trust header value without validation
const payload = packetBuffer.slice(HEADER_SIZE, HEADER_SIZE + payloadLength);`,
      correct: false,
      explanation: 'Trusting packet header values enables buffer overread. Attackers can craft packets with payload lengths exceeding actual data, causing reads beyond packet boundaries.'
    },
    {
      code: `if (payloadLength > 0) {
    for (let i = 0; i < payloadLength; i++) {
        processedBuffer[writeIndex++] = packetBuffer[HEADER_SIZE + i];
    }
}`,
      correct: false,
      explanation: 'Positive length check insufficient for safety. Large positive values can still exceed buffer boundaries, and negative lengths may be interpreted as large positive values.'
    },
    {
      code: `const availableSpace = processedBuffer.length - writeIndex;
if (payloadLength <= availableSpace) {
    // Copy without checking source buffer bounds
    for (let i = 0; i < payloadLength; i++) {
        processedBuffer[writeIndex++] = packetBuffer[HEADER_SIZE + i];
    }
}`,
      correct: false,
      explanation: 'Destination bounds checking without source validation allows buffer overread. While the output buffer is protected, reading past the input packet boundaries can expose sensitive data.'
    },
    {
      code: `try {
    for (let i = 0; i < payloadLength; i++) {
        processedBuffer[writeIndex++] = packetBuffer[HEADER_SIZE + i] || 0;
    }
} catch (e) {
    console.log('Copy failed');
}`,
      correct: false,
      explanation: 'JavaScript array access beyond bounds returns undefined rather than throwing exceptions. The || 0 fallback masks buffer overread by substituting zero values.'
    },
    {
      code: `const maxCopy = Math.min(payloadLength, packetBuffer.length - HEADER_SIZE);
for (let i = 0; i < maxCopy; i++) {
    processedBuffer[writeIndex++] = packetBuffer[HEADER_SIZE + i];
}`,
      correct: false,
      explanation: 'Partial bounds checking without destination validation can overflow the output buffer. While source reads are safe, the destination buffer capacity is not verified.'
    },
    {
      code: `if (HEADER_SIZE + payloadLength <= packetBuffer.length) {
    for (let i = 0; i < payloadLength; i++) {
        if (writeIndex < processedBuffer.length) {
            processedBuffer[writeIndex++] = packetBuffer[HEADER_SIZE + i];
        }
    }
}`,
      correct: false,
      explanation: 'Per-iteration bounds checking is inefficient and can create incomplete data. Silent truncation when destination buffer fills may corrupt packet processing logic.'
    },
    {
      code: `const safePayloadLength = Math.abs(payloadLength) % MAX_PAYLOAD_SIZE;
for (let i = 0; i < safePayloadLength; i++) {
    processedBuffer[writeIndex++] = packetBuffer[HEADER_SIZE + i];
}`,
      correct: false,
      explanation: 'Modulo bounds limiting can create unexpected payload sizes. The modulo operation may drastically change intended payload length, corrupting packet semantics.'
    },
    {
      code: `if (payloadLength.toString().length < 5) {
    for (let i = 0; i < payloadLength; i++) {
        processedBuffer[writeIndex++] = packetBuffer[HEADER_SIZE + i];
    }
}`,
      correct: false,
      explanation: 'String length validation is indirect and unreliable. Large 4-digit numbers can still cause buffer overflow, and the check has no logical relationship to buffer safety.'
    },
    {
      code: `let remainingBytes = payloadLength;
let sourcePos = HEADER_SIZE;
while (remainingBytes > 0 && sourcePos < packetBuffer.length) {
    processedBuffer[writeIndex++] = packetBuffer[sourcePos++];
    remainingBytes--;
}`,
      correct: false,
      explanation: 'While loop with source bounds checking but no destination validation. The processedBuffer can overflow if payloadLength exceeds the destination buffer capacity.'
    }
  ]
}