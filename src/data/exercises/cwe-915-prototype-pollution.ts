import type { Exercise } from '@/data/exercises'

/**
 * CWE-915 Exercise 1: Prototype Pollution via Object Path Setting
 * Based on MITRE demonstrative examples for dynamic object attribute modification
 */
export const cwe915PrototypePollution: Exercise = {
  cweId: 'CWE-915',
  name: 'Prototype Pollution - Configuration Object Setting',

  vulnerableFunction: `function setValueByPath(object, path, value) {
  const pathArray = path.split(".");
  const attributeToSet = pathArray.pop();
  let objectToModify = object;
  for (const attr of pathArray) {
    if (typeof objectToModify[attr] !== 'object') {
      objectToModify[attr] = {};
    }
    objectToModify = objectToModify[attr];
  }
  objectToModify[attributeToSet] = value;
  return object;
}`,

  vulnerableLine: `objectToModify[attributeToSet] = value;`,

  options: [
    {
      code: `const ALLOWED_PATHS = ['user.name', 'user.email', 'settings.theme'];
if (!ALLOWED_PATHS.includes(path)) throw new Error('Invalid path');
objectToModify[attributeToSet] = value;`,
      correct: true,
      explanation: `Prevent prototype pollution attacks`
    },
    {
      code: `objectToModify[attributeToSet] = value;`,
      correct: false,
      explanation: 'Unchecked dynamic property assignment enables prototype pollution. Attackers can use paths like "__proto__.isAdmin" to modify Object.prototype.'
    },
    {
      code: `if (attributeToSet !== '__proto__') objectToModify[attributeToSet] = value;`,
      correct: false,
      explanation: 'Blocking only "__proto__" is insufficient. Attackers can use "constructor.prototype" or other prototype chain manipulation paths.'
    },
    {
      code: `if (!path.includes('proto')) objectToModify[attributeToSet] = value;`,
      correct: false,
      explanation: 'String matching is easily bypassed. Attackers can use "constructor.prototype" or URL-encoded variations to avoid detection.'
    },
    {
      code: `if (typeof objectToModify[attributeToSet] === 'undefined') objectToModify[attributeToSet] = value;`,
      correct: false,
      explanation: 'Checking if property exists does not prevent prototype pollution. Prototype properties may be undefined but still dangerous to set.'
    },
    {
      code: `Object.defineProperty(objectToModify, attributeToSet, {value, writable: false});`,
      correct: false,
      explanation: 'defineProperty still allows prototype pollution if the path leads to Object.prototype. The issue is path traversal, not property mutability.'
    },
    {
      code: `if (attributeToSet.length > 0) objectToModify[attributeToSet] = value;`,
      correct: false,
      explanation: 'Length validation does not address prototype pollution. Short dangerous paths like "__proto__" or "constructor" are still valid.'
    },
    {
      code: `try { objectToModify[attributeToSet] = value; } catch(e) { /* ignore */ }`,
      correct: false,
      explanation: 'Silent error handling does not prevent prototype pollution. Most prototype pollution attacks do not throw exceptions.'
    },
    {
      code: `if (path.startsWith('user.')) objectToModify[attributeToSet] = value;`,
      correct: false,
      explanation: 'Prefix checking is insufficient. Path traversal can still occur within allowed prefixes like "user.__proto__.isAdmin".'
    },
    {
      code: `const sanitized = path.replace(/[^a-zA-Z0-9.]/g, '');
objectToModify[attributeToSet] = value;`,
      correct: false,
      explanation: 'Character filtering does not prevent prototype pollution since "constructor.prototype" contains only allowed characters.'
    }
  ]
}