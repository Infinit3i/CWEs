import type { Exercise } from '@/data/exercises'

export const cwe665SecurityFlags: Exercise = {
  cweId: 'CWE-665',
  name: 'Improper Initialization - Security Flag Management',

  vulnerableFunction: `class SecurityManager {
  constructor() {
    this.adminMode = undefined;
    this.debugEnabled = undefined;
    this.secureChannelActive = undefined;
  }

  checkAccess(userId, resource) {
    if (this.adminMode) {
      return { access: true, reason: 'Admin mode enabled' };
    }

    return this.validateUserAccess(userId, resource);
  }
}`,

  vulnerableLine: `this.adminMode = undefined;`,

  options: [
    {
      code: `this.adminMode = false; this.debugEnabled = false; this.secureChannelActive = false;`,
      correct: true,
      explanation: `Correct! Explicitly initializing security flags to false ensures secure defaults. From MITRE guidance, security-critical resources must start in known, safe states to prevent privilege escalation.`
    },
    {
      code: `this.adminMode = undefined;`,
      correct: false,
      explanation: 'Direct from MITRE: Uninitialized security flags may contain previous values. If adminMode retains a true value from memory, unauthorized users gain admin privileges, bypassing security controls.'
    },
    {
      code: `this.adminMode = true;`,
      correct: false,
      explanation: 'Initializing security flags to permissive states violates secure defaults. From MITRE examples of privilege escalation through improper initialization of access controls.'
    },
    {
      code: `// Leave adminMode uninitialized`,
      correct: false,
      explanation: 'Completely uninitialized flags create undefined behavior in security checks. Previous memory contents may enable admin mode without authorization.'
    },
    {
      code: `this.adminMode = null;`,
      correct: false,
      explanation: 'Null values in security checks may be interpreted as truthy in some contexts, potentially granting unintended access. Use explicit boolean values for security flags.'
    },
    {
      code: `this.adminMode = '';`,
      correct: false,
      explanation: 'Empty string is falsy but semantically incorrect for boolean security flags. This creates confusion and potential errors in security logic.'
    },
    {
      code: `this.adminMode = 0;`,
      correct: false,
      explanation: 'Using numeric values for boolean flags is error-prone. While 0 is falsy, it is not semantically correct for security state representation.'
    },
    {
      code: `if (process.env.ADMIN_MODE) this.adminMode = true;`,
      correct: false,
      explanation: 'Environment-based initialization without explicit false default leaves the flag undefined when the environment variable is not set, creating security vulnerabilities.'
    }
  ]
}