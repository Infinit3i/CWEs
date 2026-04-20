import type { Exercise } from '@/data/exercises'

export const cwe416BufferReuse: Exercise = {
  cweId: 'CWE-416',
  name: 'Use After Free - Memory Buffer Management',

  vulnerableFunction: `function processDataBuffers(inputData) {
  let primaryBuffer = allocateBuffer(512);
  let secondaryBuffer = allocateBuffer(512);

  // Process initial data
  copyData(primaryBuffer, inputData.slice(0, 512));

  if (inputData.length > 1024) {
    // Free secondary buffer for large inputs
    deallocateBuffer(secondaryBuffer);

    // Allocate smaller buffers for optimization
    let tempBuffer1 = allocateBuffer(256);
    let tempBuffer2 = allocateBuffer(256);
  }

  // Continue processing with secondary buffer
  copyData(secondaryBuffer, inputData.slice(512, 1024));

  return { primary: primaryBuffer, secondary: secondaryBuffer };
}`,

  vulnerableLine: `copyData(secondaryBuffer, inputData.slice(512, 1024));`,

  options: [
    {
      code: `if (!isBufferFreed(secondaryBuffer)) { copyData(secondaryBuffer, inputData.slice(512, 1024)); }`,
      correct: true,
      explanation: `Correct! Checking if the buffer is still allocated before use prevents use-after-free. This ensures we only access valid memory that hasn't been deallocated, preventing potential crashes, data corruption, or security vulnerabilities.`
    },
    {
      code: `copyData(secondaryBuffer, inputData.slice(512, 1024));`,
      correct: false,
      explanation: 'MITRE use-after-free pattern: secondaryBuffer was deallocated earlier but is still accessed. This can cause crashes, memory corruption, or allow attackers to control freed memory contents.'
    },
    {
      code: `try { copyData(secondaryBuffer, inputData.slice(512, 1024)); } catch(e) { /* ignore */ }`,
      correct: false,
      explanation: 'Exception handling cannot prevent use-after-free vulnerabilities. Memory access to freed buffer occurs before exceptions can be caught, potentially causing immediate crashes.'
    },
    {
      code: `if (secondaryBuffer !== null) { copyData(secondaryBuffer, inputData.slice(512, 1024)); }`,
      correct: false,
      explanation: 'Null check is insufficient. Deallocated memory pointers often retain their address value, appearing non-null while pointing to freed/reallocated memory.'
    },
    {
      code: `secondaryBuffer = allocateBuffer(512); copyData(secondaryBuffer, inputData.slice(512, 1024));`,
      correct: false,
      explanation: 'Reallocating before use works but wastes memory by creating new buffer instead of reusing existing one, and indicates poor memory management design.'
    },
    {
      code: `if (inputData.length <= 1024) { copyData(secondaryBuffer, inputData.slice(512, 1024)); }`,
      correct: false,
      explanation: 'This prevents use in large input cases but fails to address the fundamental issue. Buffer might be freed for other reasons, making this check insufficient.'
    },
    {
      code: `copyData(secondaryBuffer || allocateBuffer(512), inputData.slice(512, 1024));`,
      correct: false,
      explanation: 'Logical OR does not detect freed memory. Freed pointers typically remain truthy, so this fallback allocation never triggers and use-after-free persists.'
    },
    {
      code: `setTimeout(() => copyData(secondaryBuffer, inputData.slice(512, 1024)), 0);`,
      correct: false,
      explanation: 'Delaying execution does not solve use-after-free. The buffer remains freed regardless of timing, and may be reallocated for other purposes by then.'
    },
    {
      code: `if (typeof secondaryBuffer !== "undefined") { copyData(secondaryBuffer, inputData.slice(512, 1024)); }`,
      correct: false,
      explanation: 'Undefined check misses the issue. Freed memory pointers remain defined variables pointing to invalid/reallocated memory addresses.'
    },
    {
      code: `copyData(primaryBuffer, inputData.slice(512, 1024));`,
      correct: false,
      explanation: 'Using different buffer avoids use-after-free but corrupts primary buffer data and fails to process secondary data correctly, breaking application logic.'
    }
  ]
}