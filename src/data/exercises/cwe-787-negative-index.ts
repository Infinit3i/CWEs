import type { Exercise } from '@/data/exercises'

export const cwe787NegativeIndex: Exercise = {
  cweId: 'CWE-787',
  name: 'Out-of-bounds Write - String Replacement Buffer',

  vulnerableFunction: `function replaceTextInBuffer(destBuffer, searchText, replacement) {
  const foundIndex = destBuffer.indexOf(searchText);
  let writeIndex;

  if (foundIndex === -1) {
    // Not found, calculate offset from null pointer
    writeIndex = foundIndex - destBuffer.length;
  } else {
    writeIndex = foundIndex;
  }

  // Write replacement text
  for (let i = 0; i < replacement.length; i++) {
    destBuffer[writeIndex + i] = replacement[i];
  }

  return destBuffer;
}`,

  vulnerableLine: `destBuffer[writeIndex + i] = replacement[i];`,

  options: [
    {
      code: `if (foundIndex !== -1) { /* perform replacement */ } else { return destBuffer; }`,
      correct: true,
      explanation: `Correct! Checking that foundIndex is not -1 before proceeding prevents the negative index calculation. When search text is not found, we safely return the original buffer instead of attempting writes at negative indices that could corrupt memory before the buffer.`
    },
    {
      code: `writeIndex = foundIndex - destBuffer.length;`,
      correct: false,
      explanation: 'MITRE negative index pattern: When indexOf returns -1 (not found), this calculation produces large negative index. Writing at negative indices corrupts memory before the buffer start.'
    },
    {
      code: `writeIndex = Math.abs(foundIndex - destBuffer.length);`,
      correct: false,
      explanation: 'Math.abs() converts negative to positive but creates unpredictable indices. This can still write past buffer boundaries or overwrite unintended buffer locations.'
    },
    {
      code: `writeIndex = foundIndex === -1 ? 0 : foundIndex;`,
      correct: false,
      explanation: 'Writing at index 0 when text not found overwrites buffer beginning with replacement text, corrupting existing data and potentially breaking buffer contents.'
    },
    {
      code: `if (writeIndex >= 0) { destBuffer[writeIndex + i] = replacement[i]; }`,
      correct: false,
      explanation: 'This prevents negative writes but the negative writeIndex is still calculated. Also missing upper bounds check allows writes past buffer end.'
    },
    {
      code: `try { destBuffer[writeIndex + i] = replacement[i]; } catch(e) { /* ignore */ }`,
      correct: false,
      explanation: 'Exception handling cannot undo memory corruption from negative index writes. Buffer underwrite occurs before any exception handling.'
    },
    {
      code: `writeIndex = foundIndex < 0 ? destBuffer.length : foundIndex;`,
      correct: false,
      explanation: 'Writing at buffer.length when not found attempts to write past allocated memory, causing out-of-bounds write instead of underwrite.'
    },
    {
      code: `destBuffer[(writeIndex + i) % destBuffer.length] = replacement[i];`,
      correct: false,
      explanation: 'Modulo with negative numbers produces negative results in some languages. This does not reliably prevent buffer underwrite or overflow.'
    },
    {
      code: `if (foundIndex !== undefined) { /* replacement logic */ }`,
      correct: false,
      explanation: 'indexOf() returns -1 (not undefined) when not found. This condition is always true, allowing the negative index calculation to proceed.'
    },
    {
      code: `writeIndex = Math.max(0, foundIndex - destBuffer.length);`,
      correct: false,
      explanation: 'Math.max prevents negative indices but when foundIndex is -1, this sets writeIndex to 0, overwriting buffer start with replacement text.'
    }
  ]
}