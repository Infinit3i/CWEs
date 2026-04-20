import type { Exercise } from '@/data/exercises'

export const cwe665BufferManagement: Exercise = {
  cweId: 'CWE-665',
  name: 'Improper Initialization - Buffer Management System',

  vulnerableFunction: `class DataBuffer {
  constructor(size) {
    this.buffer = new Array(size);
    this.writeIndex = 0;
    this.readIndex = 0;
  }

  write(data) {
    this.buffer[this.writeIndex] = data;
    this.writeIndex = (this.writeIndex + 1) % this.buffer.length;
  }

  read() {
    const data = this.buffer[this.readIndex];
    this.readIndex = (this.readIndex + 1) % this.buffer.length;
    return data;
  }
}`,

  vulnerableLine: `this.buffer = new Array(size);`,

  options: [
    {
      code: `this.buffer = new Array(size).fill(null); this.size = size; this.itemCount = 0;`,
      correct: true,
      explanation: `Correct! Using fill(null) ensures all buffer slots start with known values, preventing access to previous data. Tracking size and item count helps maintain buffer state integrity.`
    },
    {
      code: `this.buffer = new Array(size);`,
      correct: false,
      explanation: 'Direct from MITRE: Uninitialized array elements contain undefined values or previous memory contents. Reading from unwritten positions may expose sensitive data from previous buffer uses.'
    },
    {
      code: `this.buffer = [];`,
      correct: false,
      explanation: 'Empty array initialization ignores the requested size parameter. This creates incorrect buffer behavior and fails to establish the proper circular buffer structure.'
    },
    {
      code: `this.buffer = new ArrayBuffer(size);`,
      correct: false,
      explanation: 'ArrayBuffer creates byte storage, not an array of elements. This is semantically incorrect for a data buffer that stores arbitrary values, not raw bytes.'
    },
    {
      code: `this.buffer = new Array(size).fill(undefined);`,
      correct: false,
      explanation: 'Explicitly filling with undefined is equivalent to leaving uninitialized. From MITRE examples, undefined values in buffers can leak information or cause type errors.'
    },
    {
      code: `this.buffer = Array.from({length: size});`,
      correct: false,
      explanation: 'Array.from without mapping function creates array filled with undefined values. This still allows uninitialized data to be read from buffer positions.'
    },
    {
      code: `this.buffer = new Array(); this.buffer.length = size;`,
      correct: false,
      explanation: 'Setting length without filling creates sparse array with undefined elements. Reading from unwritten positions returns undefined, potentially leaking state information.'
    },
    {
      code: `this.buffer = size > 0 ? new Array(size) : [];`,
      correct: false,
      explanation: 'Size validation does not address the core initialization issue. Even valid-sized arrays remain filled with undefined values that can leak information.'
    }
  ]
}