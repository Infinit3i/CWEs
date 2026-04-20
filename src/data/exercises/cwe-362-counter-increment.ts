import type { Exercise } from '@/data/exercises'

/**
 * CWE-362: Race Condition in Analytics Counter Service
 * Infrastructure scenario: High-frequency counter updates in analytics system
 */
export const cwe362CounterIncrement: Exercise = {
  cweId: 'CWE-362',
  name: 'Race Condition - Analytics Counter',
  language: 'Go',

  vulnerableFunction: `class AnalyticsService {
  private cache = new Map<string, number>();

  async incrementCounter(metricName: string, increment: number = 1) {
    // Get current counter value
    let currentValue = this.cache.get(metricName) || 0;

    console.log(\`Current \${metricName} count: \${currentValue}\`);

    // Calculate new value
    const newValue = currentValue + increment;

    // Simulate processing delay
    await new Promise(resolve => setTimeout(resolve, 1));

    // Update counter
    this.cache.set(metricName, newValue);

    // Persist to database periodically
    if (newValue % 100 === 0) {
      await this.persistCounterToDatabase(metricName, newValue);
    }

    return {
      metricName,
      previousValue: currentValue,
      newValue,
      increment
    };
  }

  async persistCounterToDatabase(metricName: string, value: number) {
    await Metrics.updateOne(
      { name: metricName },
      { value, lastUpdated: new Date() },
      { upsert: true }
    );
  }
}`,

  vulnerableLine: `let currentValue = this.cache.get(metricName) || 0;`,

  options: [
    {
      code: `const currentValue = this.cache.get(metricName) || 0; const newValue = currentValue + increment; const success = this.cache.compare_and_set ? this.cache.compare_and_set(metricName, currentValue, newValue) : (this.cache.set(metricName, newValue), true);`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    {
      code: `let currentValue = this.cache.get(metricName) || 0;`,
      correct: false,
      explanation: 'Race condition in counter updates causes lost increments. Multiple concurrent requests read the same value, increment it, and the last write wins, losing intermediate updates.'
    },
    {
      code: `await new Promise(resolve => setTimeout(resolve, Math.random() * 10)); let currentValue = this.cache.get(metricName) || 0;`,
      correct: false,
      explanation: 'Random delays before reading counters worsen race conditions by creating unpredictable timing windows. This increases the likelihood of concurrent access conflicts.'
    },
    {
      code: `const lockId = Math.random().toString(); let currentValue = this.cache.get(metricName) || 0;`,
      correct: false,
      explanation: 'Generating lock IDs without actual locking provides no synchronization. The read-modify-write sequence remains non-atomic, allowing concurrent updates to interfere.'
    },
    {
      code: `let currentValue = this.cache.get(metricName) || 0; if (increment > 1) { await new Promise(resolve => setTimeout(resolve, increment)); }`,
      correct: false,
      explanation: 'Delays proportional to increment size do not prevent race conditions. The fundamental non-atomic update operation allows multiple concurrent increments to be lost.'
    },
    {
      code: `const timestamp = Date.now(); let currentValue = this.cache.get(metricName) || 0; console.log(\`Reading at \${timestamp}: \${currentValue}\`);`,
      correct: false,
      explanation: 'Timestamped logging does not address race conditions. The read-increment-write sequence remains non-atomic, allowing concurrent updates to overwrite each other.'
    },
    {
      code: `let currentValue = this.cache.get(metricName) || 0; const backup = this.cache.get(metricName + '_backup') || currentValue;`,
      correct: false,
      explanation: 'Creating backup values does not prevent race conditions in the primary counter. The main read-modify-write operation remains vulnerable to concurrent access issues.'
    },
    {
      code: `const retryCount = 3; for (let i = 0; i < retryCount; i++) { let currentValue = this.cache.get(metricName) || 0; if (i > 0) await new Promise(resolve => setTimeout(resolve, 100)); }`,
      correct: false,
      explanation: 'Retry loops without proper synchronization do not fix race conditions. Each retry attempt faces the same non-atomic update vulnerability.'
    }
  ]
}