import type { Exercise } from '@/data/exercises'

/**
 * CWE-362: Race Condition in Session Validation Service
 * Enterprise scenario: User session timeout checking with concurrent access
 */
export const cwe362SessionCheck: Exercise = {
  cweId: 'CWE-362',
  name: 'Race Condition - Session Validation',

  vulnerableFunction: `class SessionManager {
  async validateAndExtendSession(sessionId: string, userId: string) {
    // Check if session exists and is valid
    const session = await Session.findOne({ sessionId });

    if (!session || session.userId !== userId) {
      throw new Error('Invalid session');
    }

    // Check if session has expired
    const now = new Date();
    if (session.expiresAt < now) {
      await Session.deleteOne({ sessionId });
      throw new Error('Session expired');
    }

    // Extend session by 30 minutes
    const newExpiry = new Date(now.getTime() + 30 * 60 * 1000);

    await Session.updateOne(
      { sessionId },
      {
        expiresAt: newExpiry,
        lastActivity: now
      }
    );

    return {
      sessionId,
      userId,
      expiresAt: newExpiry,
      extended: true
    };
  }
}`,

  vulnerableLine: `if (session.expiresAt < now) {`,

  options: [
    {
      code: `const result = await Session.findOneAndUpdate({ sessionId, userId, expiresAt: { $gte: now } }, { expiresAt: newExpiry, lastActivity: now }, { returnDocument: 'after' }); if (!result) throw new Error('Session expired or invalid');`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    {
      code: `if (session.expiresAt < now) {`,
      correct: false,
      explanation: 'Race condition allows concurrent requests to check session expiry before deletion occurs. This can result in expired sessions being extended or used after they should have been invalidated.'
    },
    {
      code: `const sessionCopy = {...session}; if (sessionCopy.expiresAt < now) {`,
      correct: false,
      explanation: 'Creating object copies does not prevent race conditions. The fundamental issue of checking expiry state before updating remains, allowing concurrent access timing issues.'
    },
    {
      code: `await new Promise(resolve => setTimeout(resolve, 50)); if (session.expiresAt < now) {`,
      correct: false,
      explanation: 'Adding delays before expiry checks worsens race conditions by extending the vulnerable timing window. This increases the likelihood of concurrent session operations interfering.'
    },
    {
      code: `const bufferTime = 1000; if (session.expiresAt.getTime() - bufferTime < now.getTime()) {`,
      correct: false,
      explanation: 'Adding buffer time to expiry checks does not solve race conditions. The check-then-update sequence remains non-atomic, allowing concurrent operations to interfere.'
    },
    {
      code: `console.log(\`Checking session \${sessionId} at \${now.toISOString()}\`); if (session.expiresAt < now) {`,
      correct: false,
      explanation: 'Logging session checks does not address race conditions. The fundamental timing issue between checking expiry and updating session state remains vulnerable.'
    },
    {
      code: `const randomDelay = Math.random() * 100; await new Promise(resolve => setTimeout(resolve, randomDelay)); if (session.expiresAt < now) {`,
      correct: false,
      explanation: 'Random delays before expiry checks create unpredictable timing windows that worsen race conditions. This increases rather than reduces the vulnerability to concurrent access.'
    },
    {
      code: `if (session.expiresAt < now) { console.log('Session expired, marking for deletion'); await new Promise(resolve => setTimeout(resolve, 10));`,
      correct: false,
      explanation: 'Delays between identifying expired sessions and deleting them extend the race condition window. Concurrent operations can still access sessions during this vulnerable period.'
    }
  ]
}