import type { Exercise } from '@/data/exercises'

/**
 * CWE-502 exercise: User session deserialization
 * Based on MITRE demonstrative examples showing unsafe deserialization
 */
export const cwe502UserSession: Exercise = {
  cweId: 'CWE-502',
  name: 'Deserialization of Untrusted Data - User Session Management',

  vulnerableFunction: `function loadUserSession(sessionToken) {
  if (!sessionToken) {
    return null;
  }

  try {
    // Decode base64 session token
    const serializedData = Buffer.from(sessionToken, 'base64').toString();

    // Deserialize user session object
    const userSession = JSON.parse(serializedData);

    // Load additional user data if session contains object references
    if (userSession.userProfile && userSession.userProfile.__proto__) {
      Object.setPrototypeOf(userSession.userProfile, userSession.userProfile.__proto__);
    }

    return userSession;
  } catch (error) {
    console.error('Session deserialization failed:', error);
    return null;
  }
}`,

  vulnerableLine: `const userSession = JSON.parse(serializedData);`,

  options: [
    {
      code: `function loadUserSession(sessionToken) {
  if (!sessionToken) return null;

  const hmac = crypto.createHmac('sha256', process.env.SESSION_SECRET);
  const [payload, signature] = sessionToken.split('.');

  if (hmac.update(payload).digest('hex') !== signature) {
    throw new Error('Invalid session signature');
  }

  const sessionData = JSON.parse(Buffer.from(payload, 'base64').toString());
  return { userId: sessionData.userId, role: sessionData.role };
}`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    // Unsafe deserialization vulnerabilities from MITRE
    {
      code: `const userSession = JSON.parse(serializedData);
if (userSession.userProfile && userSession.userProfile.__proto__) {
    Object.setPrototypeOf(userSession.userProfile, userSession.userProfile.__proto__);
}`,
      correct: false,
      explanation: 'Unsafe JSON deserialization with prototype manipulation. Attackers can inject malicious __proto__ properties to pollute object prototypes and execute arbitrary code.'
    },
    {
      code: `const sessionObj = eval('(' + serializedData + ')');
return sessionObj;`,
      correct: false,
      explanation: 'MITRE-style eval() deserialization allows direct code execution. Attackers can inject JavaScript code in the serialized data that executes during deserialization.'
    },
    {
      code: `const userSession = new Function('return ' + serializedData)();
return userSession;`,
      correct: false,
      explanation: 'Function constructor deserialization is equivalent to eval(). Malicious code in serialized data executes when the function is invoked.'
    },
    {
      code: `const vm = require('vm');
const userSession = vm.runInThisContext('(' + serializedData + ')');
return userSession;`,
      correct: false,
      explanation: 'VM context execution with untrusted data allows code execution. While vm.runInThisContext provides some isolation, it can still access the global scope.'
    },
    {
      code: `const userSession = JSON.parse(serializedData);
for (const key in userSession) {
    if (key === '__proto__') {
        Object.prototype[key] = userSession[key];
    }
}`,
      correct: false,
      explanation: 'Explicit prototype pollution vulnerability. Directly assigning to Object.prototype contaminates all objects in the application with attacker-controlled properties.'
    },
    {
      code: `const userSession = JSON.parse(serializedData, (key, value) => {
    if (typeof value === 'string' && value.startsWith('function')) {
        return eval(value);
    }
    return value;
});`,
      correct: false,
      explanation: 'JSON.parse reviver function with eval() allows code execution. Attackers can inject function strings that get evaluated during the parsing process.'
    },
    {
      code: `const userSession = require('js-yaml').load(serializedData);
return userSession;`,
      correct: false,
      explanation: 'YAML deserialization can execute arbitrary code through YAML tags and constructors. Libraries like js-yaml can instantiate objects and execute functions from YAML data.'
    },
    {
      code: `const userSession = JSON.parse(serializedData);
Object.assign(Object.prototype, userSession.globalSettings);
return userSession;`,
      correct: false,
      explanation: 'Object.assign to prototype causes prototype pollution. Attacker-controlled properties get assigned to Object.prototype, affecting all objects in the application.'
    },
    {
      code: `const userSession = JSON.parse(serializedData);
if (userSession.constructor && userSession.constructor.name === 'Object') {
    return userSession;
}`,
      correct: false,
      explanation: 'Constructor checking does not prevent prototype pollution or other deserialization attacks. The malicious properties have already been parsed and can affect the application.'
    },
    {
      code: `const userSession = require('pickle-js').load(Buffer.from(serializedData, 'base64'));
return userSession;`,
      correct: false,
      explanation: 'Pickle/pickle-js deserialization allows arbitrary code execution. Attackers can embed malicious code in pickled objects that executes during the unpickling process.'
    }
  ]
}