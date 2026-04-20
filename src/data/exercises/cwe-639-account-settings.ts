import type { Exercise } from '@/data/exercises'

/**
 * CWE-639: Authorization Bypass Through User-Controlled Key
 * Scenario: Account settings update with user ID manipulation
 * Based on MITRE patterns for parameter tampering vulnerabilities
 */
export const cwe639AccountSettings: Exercise = {
  cweId: 'CWE-639',
  name: 'Authorization Bypass - Account Settings Update',
  language: 'PHP',

  vulnerableFunction: `app.put('/api/account/settings', requireAuth, async (req, res) => {
  try {
    const {
      userId,
      email,
      phoneNumber,
      notificationPreferences,
      privacySettings,
      accountType
    } = req.body;

    // Validate required fields
    if (!userId) {
      return res.status(400).json({ error: 'User ID is required' });
    }

    // Validate email format if provided
    if (email && !/^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/.test(email)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }

    // Validate phone number format if provided
    if (phoneNumber && !/^\\+?[1-9]\\d{1,14}$/.test(phoneNumber)) {
      return res.status(400).json({ error: 'Invalid phone number format' });
    }

    // Check if user exists
    const userExists = await db.query('SELECT id FROM users WHERE id = ?', [userId]);
    if (userExists.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Update user settings
    const updateQuery = \`
      UPDATE users SET
        email = COALESCE(?, email),
        phone_number = COALESCE(?, phone_number),
        notification_prefs = COALESCE(?, notification_prefs),
        privacy_settings = COALESCE(?, privacy_settings),
        account_type = COALESCE(?, account_type),
        updated_at = NOW()
      WHERE id = ?
    \`;

    const updateValues = [
      email,
      phoneNumber,
      JSON.stringify(notificationPreferences),
      JSON.stringify(privacySettings),
      accountType,
      userId
    ];

    await db.query(updateQuery, updateValues);

    // Get updated user data
    const updatedUser = await db.query('SELECT * FROM users WHERE id = ?', [userId]);

    res.json({
      message: 'Settings updated successfully',
      user: updatedUser[0]
    });

  } catch (error) {
    res.status(500).json({ error: 'Failed to update settings' });
  }
});`,

  vulnerableLine: `await db.query(updateQuery, updateValues);`,

  options: [
    {
      code: `// Verify the requesting user can only update their own settings
const authenticatedUserId = req.user.id;

if (parseInt(userId) !== authenticatedUserId) {
  return res.status(403).json({ error: 'Access denied: cannot modify other users\' settings' });
}

await db.query(updateQuery, updateValues);`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    // Real MITRE demonstrative examples as wrong answers
    {
      code: `await db.query(updateQuery, updateValues);`,
      correct: false,
      explanation: 'Direct from MITRE CWE-639: Missing authorization check allows users to modify any account by manipulating the userId parameter. Attackers can change other users\' email addresses for account takeover, modify privacy settings to expose data, or upgrade account types for unauthorized privileges.'
    },
    {
      code: `if (userId === '1') { return res.status(403).json({ error: 'Cannot modify admin account' }); }
await db.query(updateQuery, updateValues);`,
      correct: false,
      explanation: 'Single ID protection only prevents modification of user ID 1. Attackers can still modify settings for all other users by manipulating the userId parameter to values like 2, 3, 4, etc., potentially taking over accounts or escalating privileges.'
    },
    {
      code: `const userAge = Date.now() - Date.parse(req.user.created_at);
if (userAge < 86400000) { return res.status(403).json({ error: 'Account too new' }); }
await db.query(updateQuery, updateValues);`,
      correct: false,
      explanation: 'Account age restrictions do not prevent unauthorized settings modification. While this may prevent new accounts from changing settings, established users can still modify any other user\'s settings by manipulating the userId parameter.'
    },
    {
      code: `if (accountType === 'admin') { return res.status(403).json({ error: 'Cannot set admin account type' }); }
await db.query(updateQuery, updateValues);`,
      correct: false,
      explanation: 'Field-specific validation does not implement user authorization. While preventing admin privilege escalation, users can still modify other users\' email addresses, phone numbers, and privacy settings by manipulating the userId parameter.'
    },
    {
      code: `const requestLimit = await getRequestCount(req.user.id);
if (requestLimit > 10) { return res.status(429).json({ error: 'Too many requests' }); }
await db.query(updateQuery, updateValues);`,
      correct: false,
      explanation: 'Rate limiting does not prevent unauthorized settings modification, only limits frequency. Users can still modify other users\' account settings within the rate limit by manipulating the userId parameter.'
    },
    {
      code: `const hashedUserId = crypto.createHash('md5').update(userId.toString()).digest('hex');
const updateQuery = 'UPDATE users SET ... WHERE MD5(id) = ?';
await db.query(updateQuery, [...updateValues.slice(0, -1), hashedUserId]);`,
      correct: false,
      explanation: 'Hashing the user ID does not solve the authorization problem. This only obfuscates the lookup method but users can still modify any account by providing the correct user ID to be hashed.'
    },
    {
      code: `if (req.headers['x-modification-token'] !== process.env.MODIFICATION_SECRET) { return res.status(403).json({ error: 'Missing modification token' }); }
await db.query(updateQuery, updateValues);`,
      correct: false,
      explanation: 'Shared secret authentication does not implement per-user authorization. Even with the correct token, any user with access to the secret can modify any account by manipulating the userId parameter.'
    },
    {
      code: `const encryptedUserId = encrypt(userId, req.user.sessionKey);
const decryptedUserId = decrypt(encryptedUserId, req.user.sessionKey);
await db.query(updateQuery, [...updateValues.slice(0, -1), decryptedUserId]);`,
      correct: false,
      explanation: 'Encrypting and immediately decrypting the user ID provides no security benefit. This operation has no net effect and users can still modify any account by providing any user ID in the original request.'
    },
    {
      code: `await new Promise(resolve => setTimeout(resolve, 1000));
await db.query(updateQuery, updateValues);`,
      correct: false,
      explanation: 'Adding delays does not implement authorization. While this may slow down attacks, users can still modify other users\' account settings by manipulating the userId parameter - just at a slower rate.'
    }
  ]
}