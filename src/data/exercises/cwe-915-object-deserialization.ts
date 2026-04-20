import type { Exercise } from '@/data/exercises'

/**
 * CWE-915 Exercise 4: Unsafe Object Deserialization
 * Based on PHP unserialize() and Node.js object construction vulnerabilities
 */
export const cwe915ObjectDeserialization: Exercise = {
  cweId: 'CWE-915',
  name: 'Object Deserialization - Session Data Reconstruction',
  language: 'JavaScript',

  vulnerableFunction: `function deserializeSession(sessionData) {
  const parsed = JSON.parse(sessionData);
  const session = {};

  // Reconstruct session object from serialized data
  for (const [path, value] of Object.entries(parsed)) {
    const keys = path.split('.');
    let current = session;

    for (let i = 0; i < keys.length - 1; i++) {
      const key = keys[i];
      if (!current[key]) current[key] = {};
      current = current[key];
    }

    current[keys[keys.length - 1]] = value;
  }

  return session;
}`,

  vulnerableLine: `current[keys[keys.length - 1]] = value;`,

  options: [
    {
      code: `const SAFE_PREFIXES = ['user.', 'preferences.', 'cart.'];
if (SAFE_PREFIXES.some(prefix => path.startsWith(prefix))) {
  current[keys[keys.length - 1]] = value;
}`,
      correct: true,
      explanation: `Prevent object deserialization attacks`
    },
    {
      code: `current[keys[keys.length - 1]] = value;`,
      correct: false,
      explanation: 'Unchecked object property assignment during deserialization enables prototype pollution via crafted session data.'
    },
    {
      code: `if (keys[keys.length - 1] !== '__proto__') current[keys[keys.length - 1]] = value;`,
      correct: false,
      explanation: 'Blocking only "__proto__" is insufficient. Attackers can use intermediate paths like "constructor.prototype" to achieve pollution.'
    },
    {
      code: `if (!path.includes('proto')) current[keys[keys.length - 1]] = value;`,
      correct: false,
      explanation: 'String matching is easily bypassed using "constructor.prototype" or encoded variations that do not contain "proto".'
    },
    {
      code: `Object.defineProperty(current, keys[keys.length - 1], {value, enumerable: false});`,
      correct: false,
      explanation: 'defineProperty still enables prototype pollution if the path leads to Object.prototype. Enumerable setting does not prevent the attack.'
    },
    {
      code: `const key = keys[keys.length - 1];
if (current.hasOwnProperty(key) || key in current) current[key] = value;`,
      correct: false,
      explanation: 'Property existence checks do not prevent prototype pollution. Properties like "__proto__" exist in the prototype chain.'
    },
    {
      code: `if (typeof value !== 'function') current[keys[keys.length - 1]] = value;`,
      correct: false,
      explanation: 'Type filtering does not prevent prototype pollution. Dangerous values like true or strings can still pollute Object.prototype.'
    },
    {
      code: `const frozenSession = Object.freeze(session);
current[keys[keys.length - 1]] = value;
return frozenSession;`,
      correct: false,
      explanation: 'Freezing the return value does not prevent prototype pollution during construction. The pollution occurs before freezing.'
    },
    {
      code: `if (keys.length <= 3) current[keys[keys.length - 1]] = value;`,
      correct: false,
      explanation: 'Path length limits do not prevent prototype pollution. Short paths like "__proto__.isAdmin" are still dangerous.'
    },
    {
      code: `const sanitized = keys.map(k => k.replace(/[^a-zA-Z0-9]/g, ''));
current[sanitized[sanitized.length - 1]] = value;`,
      correct: false,
      explanation: 'Character sanitization breaks legitimate keys and does not prevent prototype pollution since "constructor" and "prototype" contain only allowed characters.'
    }
  ]
}