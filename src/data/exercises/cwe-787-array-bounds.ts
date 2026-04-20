import type { Exercise } from '@/data/exercises'

export const cwe787ArrayBounds: Exercise = {
  cweId: 'CWE-787',
  name: 'Out-of-bounds Write - Widget List Management',

  vulnerableFunction: `function initializeWidgets(numWidgets) {
  const widgetList = new Array(numWidgets);

  // Initialize each widget
  for (let i = 0; i < numWidgets; i++) {
    widgetList[i] = { id: i, active: true };
  }

  // Add null terminator for compatibility
  widgetList[numWidgets] = null;

  return widgetList;
}`,

  vulnerableLine: `widgetList[numWidgets] = null;`,

  options: [
    {
      code: `const widgetList = new Array(numWidgets + 1); /* ... */ widgetList[numWidgets] = null;`,
      correct: true,
      explanation: `Correct! Allocating numWidgets + 1 elements provides space for the null terminator. Valid indices are [0, numWidgets], so setting widgetList[numWidgets] = null is within bounds and properly terminates the array.`
    },
    {
      code: `widgetList[numWidgets] = null;`,
      correct: false,
      explanation: 'MITRE off-by-one pattern: Array allocated with numWidgets elements has valid indices [0, numWidgets-1]. Writing to index numWidgets exceeds buffer bounds, potentially corrupting adjacent memory.'
    },
    {
      code: `if (numWidgets > 0) widgetList[numWidgets] = null;`,
      correct: false,
      explanation: 'Checking numWidgets > 0 does not address the bounds issue. This still writes past the allocated array when numWidgets equals array length.'
    },
    {
      code: `widgetList[numWidgets - 1] = null;`,
      correct: false,
      explanation: 'This overwrites the last valid widget with null instead of adding a terminator, losing data and defeating the purpose of null termination.'
    },
    {
      code: `try { widgetList[numWidgets] = null; } catch(e) { widgetList.push(null); }`,
      correct: false,
      explanation: 'Exception handling cannot undo memory corruption. The out-of-bounds write occurs before any exception handling can prevent it.'
    },
    {
      code: `widgetList.length = numWidgets + 1; widgetList[numWidgets] = null;`,
      correct: false,
      explanation: 'Extending array length after creation may not allocate contiguous memory and can cause performance issues. Original allocation should account for needed size.'
    },
    {
      code: `widgetList[Math.min(numWidgets, widgetList.length - 1)] = null;`,
      correct: false,
      explanation: 'This prevents out-of-bounds write but overwrites the last widget instead of adding a proper terminator, corrupting widget data.'
    },
    {
      code: `if (widgetList.length > numWidgets) widgetList[numWidgets] = null;`,
      correct: false,
      explanation: 'Since array was allocated with exactly numWidgets elements, this condition is never true, so null terminator is never added.'
    },
    {
      code: `delete widgetList[numWidgets]; widgetList[numWidgets] = null;`,
      correct: false,
      explanation: 'Delete does not prevent out-of-bounds access. This still attempts to write past allocated memory boundaries.'
    },
    {
      code: `Object.defineProperty(widgetList, numWidgets, {value: null});`,
      correct: false,
      explanation: 'Object.defineProperty does not prevent out-of-bounds access on arrays. This still attempts to define a property at an invalid array index.'
    }
  ]
}