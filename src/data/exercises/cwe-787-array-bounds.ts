import type { Exercise } from '@/data/exercises'

export const cwe787ArrayBounds: Exercise = {
  cweId: 'CWE-787',
  name: 'Out-of-bounds Write - Widget List Management',
  language: 'C',

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
      explanation: `Allocate extra space for null terminator`
    },
    {
      code: `widgetList[numWidgets] = null;`,
      correct: false,
      explanation: 'Writing past array bounds corrupts memory'
    },
    {
      code: `if (numWidgets > 0) widgetList[numWidgets] = null;`,
      correct: false,
      explanation: 'Still writes past allocated array bounds'
    },
    {
      code: `widgetList[numWidgets - 1] = null;`,
      correct: false,
      explanation: 'Overwrites valid widget data with null'
    },
    {
      code: `try { widgetList[numWidgets] = null; } catch(e) { widgetList.push(null); }`,
      correct: false,
      explanation: 'Try-catch cannot undo memory corruption'
    },
    {
      code: `widgetList.length = numWidgets + 1; widgetList[numWidgets] = null;`,
      correct: false,
      explanation: 'Extending length after creation causes performance issues'
    },
    {
      code: `widgetList[Math.min(numWidgets, widgetList.length - 1)] = null;`,
      correct: false,
      explanation: 'Overwrites last widget instead of adding terminator'
    },
    {
      code: `if (widgetList.length > numWidgets) widgetList[numWidgets] = null;`,
      correct: false,
      explanation: 'Condition never true, terminator never added'
    },
    {
      code: `delete widgetList[numWidgets]; widgetList[numWidgets] = null;`,
      correct: false,
      explanation: 'Delete does not prevent out-of-bounds access'
    },
    {
      code: `Object.defineProperty(widgetList, numWidgets, {value: null});`,
      correct: false,
      explanation: 'defineProperty cannot access invalid array indices'
    }
  ]
}