import type { Exercise } from '@/data/exercises'

export const cwe20ArraySize: Exercise = {
  cweId: 'CWE-20',
  name: 'Improper Input Validation - Dynamic Array Creation',

  vulnerableFunction: `function createWidgetList(untrustedListSize) {
  // Validate against negative sizes
  if (untrustedListSize < 0) {
    throw new Error('Negative list size not allowed');
  }

  // Create widget array
  const widgetList = new Array(untrustedListSize);

  // Initialize first widget
  widgetList[0] = createWidget('default');

  // Process remaining widgets
  for (let i = 1; i < untrustedListSize; i++) {
    widgetList[i] = createWidget('item_' + i);
  }

  return widgetList;
}`,

  vulnerableLine: `widgetList[0] = createWidget('default');`,

  options: [
    {
      code: `if (untrustedListSize <= 0) { throw new Error('Invalid list size'); } const widgetList = new Array(untrustedListSize);`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    {
      code: `widgetList[0] = createWidget('default');`,
      correct: false,
      explanation: 'MITRE zero-length array pattern: Validation rejects negative values but allows zero. When untrustedListSize is 0, array has no elements, causing index 0 access to be out-of-bounds and potentially crashing the application.'
    },
    {
      code: `if (widgetList.length > 0) { widgetList[0] = createWidget('default'); }`,
      correct: false,
      explanation: 'Length check prevents crash but creates inconsistent behavior. Sometimes the function returns array with first element, sometimes without, depending on input size.'
    },
    {
      code: `try { widgetList[0] = createWidget('default'); } catch(e) { /* ignore */ }`,
      correct: false,
      explanation: 'Exception handling masks the underlying validation issue. Zero-length arrays indicate invalid input that should be rejected upfront rather than handled reactively.'
    },
    {
      code: `widgetList[0] = widgetList[0] || createWidget('default');`,
      correct: false,
      explanation: 'Conditional assignment does not prevent out-of-bounds access. Reading widgetList[0] on zero-length array still causes the bounds violation before assignment.'
    },
    {
      code: `const minSize = Math.max(1, untrustedListSize); const widgetList = new Array(minSize);`,
      correct: false,
      explanation: 'Automatic adjustment silently changes user intent. Zero or negative input should trigger validation error rather than silent correction to different size.'
    },
    {
      code: `if (untrustedListSize !== 0) { widgetList[0] = createWidget('default'); }`,
      correct: false,
      explanation: 'Zero check prevents this specific crash but the function still creates zero-length array, leading to inconsistent return values and potential issues elsewhere.'
    },
    {
      code: `widgetList.push(createWidget('default'));`,
      correct: false,
      explanation: 'Push method avoids bounds error but changes array from fixed-size Array(n) to dynamic array, altering expected memory layout and function behavior.'
    },
    {
      code: `if (Array.isArray(widgetList) && widgetList.length) { widgetList[0] = createWidget('default'); }`,
      correct: false,
      explanation: 'Array validation prevents crash but creates conditional behavior. Function should either always succeed with valid input or fail with clear error message.'
    },
    {
      code: `Object.defineProperty(widgetList, 0, {value: createWidget('default')});`,
      correct: false,
      explanation: 'defineProperty does not prevent out-of-bounds access on arrays. This still attempts to define property at invalid index when array length is 0.'
    }
  ]
}