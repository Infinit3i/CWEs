import type { Exercise } from '@/data/exercises'

/**
 * CWE-915 Exercise 5: Dynamic Property Access in API Handler
 * Based on dynamic object modification through user-controlled property names
 */
export const cwe915DynamicProperty: Exercise = {
  cweId: 'CWE-915',
  name: 'Dynamic Property Access - REST API Handler',

  vulnerableFunction: `function updateResourceProperty(resource, propertyName, propertyValue) {
  // Dynamic property update based on API request
  const parts = propertyName.split('.');
  let current = resource;

  // Navigate to parent object
  for (let i = 0; i < parts.length - 1; i++) {
    if (!current[parts[i]]) {
      current[parts[i]] = {};
    }
    current = current[parts[i]];
  }

  // Set the final property
  const finalProp = parts[parts.length - 1];
  current[finalProp] = propertyValue;

  return resource;
}`,

  vulnerableLine: `current[finalProp] = propertyValue;`,

  options: [
    {
      code: `const ALLOWED_PROPERTIES = new Set(['title', 'description', 'tags', 'metadata.author', 'metadata.created']);
if (ALLOWED_PROPERTIES.has(propertyName)) {
  current[finalProp] = propertyValue;
}`,
      correct: true,
      explanation: `Correct! Using a Set-based allowlist of specific property paths prevents both prototype pollution and unauthorized property modification. This ensures only legitimate API properties can be updated.`
    },
    {
      code: `current[finalProp] = propertyValue;`,
      correct: false,
      explanation: 'Direct from MITRE: Unchecked dynamic property assignment allows attackers to modify arbitrary object properties including prototype chain pollution.'
    },
    {
      code: `if (propertyName.charAt(0) !== '_') current[finalProp] = propertyValue;`,
      correct: false,
      explanation: 'Convention-based filtering is insufficient. Dangerous properties like "__proto__" or sensitive business logic properties may not follow underscore conventions.'
    },
    {
      code: `if (finalProp !== 'constructor') current[finalProp] = propertyValue;`,
      correct: false,
      explanation: 'Blocking single dangerous properties is inadequate. Multiple attack vectors exist (__proto__, prototype, other sensitive properties).'
    },
    {
      code: `if (current.hasOwnProperty(finalProp)) current[finalProp] = propertyValue;`,
      correct: false,
      explanation: 'Existing property check does not prevent prototype pollution. "__proto__" exists in the prototype chain and hasOwnProperty may return false but assignment still occurs.'
    },
    {
      code: `try {
  current[finalProp] = propertyValue;
  } catch (e) {
    console.log('Property update failed');
  }`,
      correct: false,
      explanation: 'Error handling does not prevent prototype pollution. Most prototype pollution attacks succeed without throwing exceptions.'
    },
    {
      code: `if (typeof current[finalProp] !== 'function') current[finalProp] = propertyValue;`,
      correct: false,
      explanation: 'Type checking existing values does not prevent prototype pollution or unauthorized modification of non-function sensitive properties.'
    },
    {
      code: `const descriptor = Object.getOwnPropertyDescriptor(current, finalProp);
if (!descriptor || descriptor.writable) current[finalProp] = propertyValue;`,
      correct: false,
      explanation: 'Property descriptor checks do not prevent prototype pollution. Prototype chain properties may have different descriptors than expected.'
    },
    {
      code: `if (propertyName.split('.').length <= 2) current[finalProp] = propertyValue;`,
      correct: false,
      explanation: 'Path depth limits do not prevent attacks. Simple paths like "__proto__.isAdmin" are within the limit but still dangerous.'
    },
    {
      code: `Object.freeze(current);
current[finalProp] = propertyValue;`,
      correct: false,
      explanation: 'Freezing objects after modification is ineffective. The freeze occurs too late to prevent the dangerous assignment.'
    }
  ]
}