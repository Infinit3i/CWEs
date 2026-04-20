import type { Exercise } from '@/data/exercises'

export const cwe665UserSession: Exercise = {
  cweId: 'CWE-665',
  name: 'Improper Initialization - User Session State',

  vulnerableFunction: `class UserSession {
  constructor(userId) {
    this.userId = userId;
    this.permissions = {};
    this.loginTime = Date.now();
  }

  hasPermission(action) {
    return this.permissions[action] === true;
  }

  addPermission(action) {
    this.permissions[action] = true;
  }
}`,

  vulnerableLine: `this.permissions = {};`,

  options: [
    {
      code: `this.permissions = Object.create(null); this.isAuthenticated = false; this.permissionCount = 0;`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    {
      code: `this.permissions = {};`,
      correct: false,
      explanation: 'Plain object initialization may inherit prototype properties. Uninitialized permissions object could have hasOwnProperty vulnerabilities or inherit unexpected permissions.'
    },
    {
      code: `this.permissions = new Array();`,
      correct: false,
      explanation: 'Using arrays for key-value permission storage is inefficient and semantically incorrect. Array indices do not properly represent permission names.'
    },
    {
      code: `this.permissions = null;`,
      correct: false,
      explanation: 'Null permissions cause immediate failures when checking access. hasPermission() will throw errors trying to access properties of null.'
    },
    {
      code: `// Leave permissions uninitialized`,
      correct: false,
      explanation: 'From MITRE examples, uninitialized objects may contain previous session data. Users could inherit permissions from previous sessions, causing privilege escalation.'
    },
    {
      code: `this.permissions = undefined;`,
      correct: false,
      explanation: 'Undefined permissions create runtime errors when accessing permission properties. This leads to application crashes during permission checks.'
    },
    {
      code: `this.permissions = { admin: false };`,
      correct: false,
      explanation: 'Pre-populating with admin flag suggests permissions might not be properly controlled. Session permissions should be explicitly granted, not pre-initialized with specific roles.'
    },
    {
      code: `this.permissions = JSON.parse('{}');`,
      correct: false,
      explanation: 'Using JSON.parse for simple object creation is unnecessary and may fail if the string is malformed. Direct object initialization is simpler and safer.'
    }
  ]
}