import type { Exercise } from '@/data/exercises'

export const cwe665CryptoState: Exercise = {
  cweId: 'CWE-665',
  name: 'Improper Initialization - Cryptographic State Management',

  vulnerableFunction: `class CryptoManager {
  constructor() {
    this.keyCache = {};
    this.encryptionEnabled = undefined;
    this.algorithm = undefined;
  }

  encrypt(data, keyId) {
    if (!this.encryptionEnabled) {
      return data; // Return plaintext if encryption disabled
    }

    const key = this.keyCache[keyId];
    return this.performEncryption(data, key, this.algorithm);
  }
}`,

  vulnerableLine: `this.encryptionEnabled = undefined;`,

  options: [
    {
      code: `this.encryptionEnabled = true; this.algorithm = 'AES-256-GCM'; this.keyCache = new Map();`,
      correct: true,
      explanation: `Correct! Initializing encryption to enabled by default ensures secure operation. Setting a strong default algorithm prevents weak crypto, and using Map for key cache provides better security than plain objects.`
    },
    {
      code: `this.encryptionEnabled = undefined;`,
      correct: false,
      explanation: 'Direct from MITRE: Uninitialized encryption flag may contain previous values. If encryptionEnabled retains false from memory, sensitive data is transmitted in plaintext, violating confidentiality.'
    },
    {
      code: `this.encryptionEnabled = false;`,
      correct: false,
      explanation: 'Defaulting encryption to disabled violates secure defaults principle. From MITRE examples, improper initialization of security controls leads to data exposure.'
    },
    {
      code: `this.encryptionEnabled = null;`,
      correct: false,
      explanation: 'Null values in boolean security checks may be interpreted inconsistently. This creates ambiguous security state that could default to insecure operation.'
    },
    {
      code: `// Leave encryptionEnabled uninitialized`,
      correct: false,
      explanation: 'Completely uninitialized crypto state may contain arbitrary values from memory. Previous instances might have left encryption disabled, causing data leakage.'
    },
    {
      code: `this.encryptionEnabled = 0;`,
      correct: false,
      explanation: 'Using numeric values for boolean crypto flags is error-prone. While 0 is falsy, it is semantically incorrect and may cause confusion in security logic.'
    },
    {
      code: `this.encryptionEnabled = '';`,
      correct: false,
      explanation: 'Empty string is falsy but inappropriate for crypto flags. This creates semantic confusion and potential errors in encryption decision logic.'
    },
    {
      code: `if (process.env.ENCRYPT) this.encryptionEnabled = true;`,
      correct: false,
      explanation: 'Environment-dependent initialization without explicit defaults leaves encryption disabled when environment variable is missing, violating secure defaults.'
    }
  ]
}