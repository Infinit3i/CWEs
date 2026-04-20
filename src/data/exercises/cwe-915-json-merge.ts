import type { Exercise } from '@/data/exercises'

/**
 * CWE-915 Exercise 3: Unsafe JSON Merge in Configuration System
 * Based on object merging vulnerabilities leading to prototype pollution
 */
export const cwe915JsonMerge: Exercise = {
  cweId: 'CWE-915',
  name: 'JSON Merge - Configuration Override',

  vulnerableFunction: `function mergeConfig(baseConfig, userConfig) {
  function deepMerge(target, source) {
    for (const key in source) {
      if (source[key] && typeof source[key] === 'object') {
        target[key] = target[key] || {};
        deepMerge(target[key], source[key]);
      } else {
        target[key] = source[key];
      }
    }
    return target;
  }

  return deepMerge(baseConfig, userConfig);
}`,

  vulnerableLine: `target[key] = source[key];`,

  options: [
    {
      code: `if (key !== '__proto__' && key !== 'constructor' && key !== 'prototype') {
  target[key] = source[key];
}`,
      correct: true,
      explanation: `Validate merge operations`
    },
    {
      code: `target[key] = source[key];`,
      correct: false,
      explanation: 'Unchecked property assignment during object merging enables prototype pollution via paths like {"__proto__": {"isAdmin": true}}.'
    },
    {
      code: `if (source.hasOwnProperty(key)) target[key] = source[key];`,
      correct: false,
      explanation: 'hasOwnProperty does not prevent prototype pollution. Malicious JSON can include "__proto__" as an own property that bypasses this check.'
    },
    {
      code: `Object.assign(target, source);`,
      correct: false,
      explanation: 'Object.assign is vulnerable to prototype pollution when source contains "__proto__" properties, making this even less secure.'
    },
    {
      code: `target[key] = JSON.parse(JSON.stringify(source[key]));`,
      correct: false,
      explanation: 'Deep cloning the value does not prevent prototype pollution. The issue is setting properties on prototype chain, not value references.'
    },
    {
      code: `if (key.length > 0) target[key] = source[key];`,
      correct: false,
      explanation: 'Length validation does not prevent prototype pollution. Dangerous keys like "__proto__" have positive length.'
    },
    {
      code: `try { target[key] = source[key]; } catch {} `,
      correct: false,
      explanation: 'Error handling does not prevent prototype pollution. Most prototype pollution attacks complete successfully without throwing errors.'
    },
    {
      code: `if (typeof key === 'string') target[key] = source[key];`,
      correct: false,
      explanation: 'Type checking does not prevent prototype pollution since "__proto__" and "constructor" are string keys.'
    },
    {
      code: `const descriptor = Object.getOwnPropertyDescriptor(source, key);
if (descriptor) target[key] = source[key];`,
      correct: false,
      explanation: 'Property descriptor checking does not prevent prototype pollution. Malicious properties like "__proto__" can have valid descriptors.'
    },
    {
      code: `if (!key.includes('.')) target[key] = source[key];`,
      correct: false,
      explanation: 'Checking for dots does not prevent prototype pollution. Direct attacks use "__proto__" without dots to pollute Object.prototype.'
    }
  ]
}