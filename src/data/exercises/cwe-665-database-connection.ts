import type { Exercise } from '@/data/exercises'

export const cwe665DatabaseConnection: Exercise = {
  cweId: 'CWE-665',
  name: 'Improper Initialization - Database Connection Pool',
  language: 'PHP',

  vulnerableFunction: `class DatabaseManager {
  constructor() {
    this.connectionPool = {};
    this.maxConnections = 10;
  }

  getConnection(databaseName) {
    if (!this.connectionPool[databaseName]) {
      this.connectionPool[databaseName] = this.createConnection(databaseName);
    }
    return this.connectionPool[databaseName];
  }
}`,

  vulnerableLine: `this.connectionPool = {};`,

  options: [
    {
      code: `this.connectionPool = new Map(); this.activeConnections = 0;`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    {
      code: `this.connectionPool = {};`,
      correct: false,
      explanation: 'Uninitialized properties may contain previous values or unexpected data. The connection pool might retain connections from previous instances, causing security or stability issues.'
    },
    {
      code: `this.connectionPool = null;`,
      correct: false,
      explanation: 'Initializing to null creates immediate failure when accessing connectionPool properties. This will cause runtime errors when trying to store or retrieve connections.'
    },
    {
      code: `this.connectionPool = undefined;`,
      correct: false,
      explanation: 'Explicitly setting to undefined is equivalent to leaving uninitialized. From MITRE examples, this creates unpredictable behavior when the pool is first accessed.'
    },
    {
      code: `// Leave connectionPool uninitialized`,
      correct: false,
      explanation: 'Completely uninitialized properties may contain arbitrary data from memory. This can lead to accessing previous connection data or cause type errors.'
    },
    {
      code: `this.connectionPool = Object.create(null);`,
      correct: false,
      explanation: 'While creating a clean object, this lacks proper initialization of related state like connection counts, leading to inconsistent pool management.'
    },
    {
      code: `this.connectionPool = [];`,
      correct: false,
      explanation: 'Using an array for key-value storage is inappropriate and leads to incorrect connection management. Database names as indices create sparse, inefficient arrays.'
    },
    {
      code: `if (!this.connectionPool) this.connectionPool = {};`,
      correct: false,
      explanation: 'Lazy initialization in the constructor indicates poor design. Constructor should establish the complete initial state rather than deferring initialization.'
    }
  ]
}