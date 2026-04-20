import type { Exercise } from '@/data/exercises'

export const cwe125ConfigParser: Exercise = {
  cweId: 'CWE-125',
  name: 'Out-of-bounds Read - Configuration File Parser',

  vulnerableFunction: `function parseConfigSection(configLines, sectionIndex) {
  const MAX_LINES = 1000;
  let sectionData = {};

  // Validate section index
  if (sectionIndex < MAX_LINES) {
    // Read section header
    const headerLine = configLines[sectionIndex];

    // Parse section content
    let lineIndex = sectionIndex + 1;
    while (lineIndex < configLines.length) {
      const currentLine = configLines[lineIndex];

      if (currentLine.startsWith('[')) {
        break; // Next section found
      }

      const [key, value] = currentLine.split('=');
      sectionData[key.trim()] = value.trim();
      lineIndex++;
    }
  }

  return sectionData;
}`,

  vulnerableLine: `const headerLine = configLines[sectionIndex];`,

  options: [
    {
      code: `if (sectionIndex >= 0 && sectionIndex < Math.min(configLines.length, MAX_LINES)) { const headerLine = configLines[sectionIndex]; }`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    {
      code: `const headerLine = configLines[sectionIndex];`,
      correct: false,
      explanation: 'MITRE missing minimum bounds pattern: Only validates against MAX_LINES constant, not actual array length or negative values. Negative sectionIndex or index exceeding configLines.length causes out-of-bounds reads.'
    },
    {
      code: `if (sectionIndex < configLines.length) { const headerLine = configLines[sectionIndex]; }`,
      correct: false,
      explanation: 'Upper bound check missing negative validation. Negative indices can access unintended array elements or undefined memory, potentially exposing configuration data or causing crashes.'
    },
    {
      code: `try { const headerLine = configLines[sectionIndex]; } catch(e) { return {}; }`,
      correct: false,
      explanation: 'Exception handling after out-of-bounds read is too late. Memory access at invalid index occurs before exception handling can prevent potential data exposure.'
    },
    {
      code: `if (typeof sectionIndex === 'number' && sectionIndex < MAX_LINES) { const headerLine = configLines[sectionIndex]; }`,
      correct: false,
      explanation: 'Type checking allows negative numbers. Negative values are valid numbers but cause out-of-bounds reads when used as array indices in configuration parsing.'
    },
    {
      code: `const safeIndex = Math.max(0, Math.min(sectionIndex, configLines.length - 1)); const headerLine = configLines[safeIndex];`,
      correct: false,
      explanation: 'Index clamping prevents crashes but returns wrong configuration section. Reading different section than requested provides incorrect configuration data to the application.'
    },
    {
      code: `if (configLines[sectionIndex]) { const headerLine = configLines[sectionIndex]; }`,
      correct: false,
      explanation: 'Truthy check performs the out-of-bounds read during the condition check itself. This does not prevent accessing invalid memory at negative or oversized indices.'
    },
    {
      code: `if (sectionIndex && sectionIndex < MAX_LINES) { const headerLine = configLines[sectionIndex]; }`,
      correct: false,
      explanation: 'Truthy check allows negative values. Negative numbers are truthy, so this validation fails to prevent negative index out-of-bounds reads in configuration parsing.'
    },
    {
      code: `if (!isNaN(sectionIndex) && sectionIndex < MAX_LINES) { const headerLine = configLines[sectionIndex]; }`,
      correct: false,
      explanation: 'NaN check does not validate range or actual array bounds. Negative numbers and indices exceeding array length are not NaN but still cause invalid memory access.'
    },
    {
      code: `const headerLine = configLines[sectionIndex] || '[Default]';`,
      correct: false,
      explanation: 'Fallback value does not prevent out-of-bounds read. The array access occurs before the OR operation, potentially reading invalid memory before providing the default.'
    }
  ]
}