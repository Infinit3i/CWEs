import type { Exercise } from '@/data/exercises'

export const cwe668DatabaseRecords: Exercise = {
  cweId: 'CWE-668',
  name: 'Exposure of Resource to Wrong Sphere - Database Record Access',

  vulnerableFunction: `function getUserRecord(requestUserId, targetRecordId) {
  const db = require('./database');

  // Fetch user record by ID
  const query = 'SELECT * FROM user_profiles WHERE id = ?';
  const record = db.query(query, [targetRecordId]);

  if (record) {
    return record;
  }

  throw new Error('Record not found');
}`,

  vulnerableLine: `const record = db.query(query, [targetRecordId]);`,

  options: [
    {
      code: `const query = 'SELECT * FROM user_profiles WHERE id = ? AND user_id = ?'; const record = db.query(query, [targetRecordId, requestUserId]);`,
      correct: true,
      explanation: `Correct! Adding a user_id constraint ensures users can only access records within their authorized sphere. This prevents horizontal privilege escalation by validating ownership.`
    },
    {
      code: `const record = db.query(query, [targetRecordId]);`,
      correct: false,
      explanation: 'Direct from MITRE: Missing authorization check allows users to access any record by guessing IDs. This exposes resources outside their intended sphere.'
    },
    {
      code: `const record = db.query(query, [targetRecordId]); if (record && record.user_id !== requestUserId) return null;`,
      correct: false,
      explanation: 'Post-query filtering still retrieves the unauthorized record from the database. This may leak information through timing attacks or error messages.'
    },
    {
      code: `if (targetRecordId > 0) { const record = db.query(query, [targetRecordId]); }`,
      correct: false,
      explanation: 'Input validation on record ID format does not prevent access to records belonging to other users. Authorization checks are still missing.'
    },
    {
      code: `const query = 'SELECT id, name FROM user_profiles WHERE id = ?'; const record = db.query(query, [targetRecordId]);`,
      correct: false,
      explanation: 'Limiting returned columns reduces information exposure but still allows access to records outside the user\'s sphere. Authorization is the core issue.'
    },
    {
      code: `const record = db.query(query, [parseInt(targetRecordId)]);`,
      correct: false,
      explanation: 'Type casting to integer does not address the authorization flaw. Users can still access any numeric record ID regardless of ownership.'
    },
    {
      code: `if (requestUserId && targetRecordId) { const record = db.query(query, [targetRecordId]); }`,
      correct: false,
      explanation: 'Checking for non-null parameters does not validate that the requesting user owns the target record. This still allows unauthorized access.'
    },
    {
      code: `const query = 'SELECT * FROM user_profiles WHERE id = ? LIMIT 1'; const record = db.query(query, [targetRecordId]);`,
      correct: false,
      explanation: 'Adding LIMIT 1 does not prevent accessing records outside the user\'s authorized sphere. The fundamental authorization issue remains.'
    }
  ]
}