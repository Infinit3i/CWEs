import type { Exercise } from '@/data/exercises'

/**
 * CWE-639: Authorization Bypass Through User-Controlled Key
 * Scenario: API key management endpoint with authorization bypass
 * Based on MITRE patterns for key-based access control vulnerabilities
 */
export const cwe639ApiKeys: Exercise = {
  cweId: 'CWE-639',
  name: 'Authorization Bypass - API Key Management',

  vulnerableFunction: `app.get('/api/keys/:keyId', requireAuthentication, async (req, res) => {
  try {
    const keyId = req.params.keyId;

    // Validate key ID format (should be alphanumeric)
    if (!/^[a-zA-Z0-9]{16}$/.test(keyId)) {
      return res.status(400).json({ error: 'Invalid key ID format' });
    }

    // Get API key details from database
    const keyQuery = \`
      SELECT ak.id, ak.name, ak.key_value, ak.permissions, ak.expires_at,
             ak.created_at, ak.last_used, ak.usage_count, ak.owner_id,
             u.email as owner_email, u.company_name
      FROM api_keys ak
      JOIN users u ON ak.owner_id = u.id
      WHERE ak.id = ? AND ak.status = 'active'
    \`;

    const keyResult = await db.query(keyQuery, [keyId]);

    if (keyResult.length === 0) {
      return res.status(404).json({ error: 'API key not found or inactive' });
    }

    const apiKey = keyResult[0];

    // Check if key has expired
    if (apiKey.expires_at && new Date(apiKey.expires_at) < new Date()) {
      return res.status(410).json({ error: 'API key has expired' });
    }

    // Get usage statistics
    const usageQuery = 'SELECT DATE(used_at) as date, COUNT(*) as requests FROM api_usage WHERE key_id = ? GROUP BY DATE(used_at) ORDER BY date DESC LIMIT 30';
    const usageStats = await db.query(usageQuery, [keyId]);

    // Return comprehensive key information
    res.json({
      apiKey: {
        id: apiKey.id,
        name: apiKey.name,
        keyValue: apiKey.key_value,
        permissions: apiKey.permissions.split(','),
        expiresAt: apiKey.expires_at,
        createdAt: apiKey.created_at,
        lastUsed: apiKey.last_used,
        totalUsage: apiKey.usage_count,
        owner: {
          email: apiKey.owner_email,
          company: apiKey.company_name
        },
        usageStats: usageStats
      }
    });

  } catch (error) {
    res.status(500).json({ error: 'Failed to retrieve API key information' });
  }
});`,

  vulnerableLine: `const keyResult = await db.query(keyQuery, [keyId]);`,

  options: [
    {
      code: `// Verify the requesting user owns this API key
const currentUserId = req.user.id;
const currentUserRole = req.user.role;

const keyQuery = \`
  SELECT ak.id, ak.name, ak.key_value, ak.permissions, ak.expires_at,
         ak.created_at, ak.last_used, ak.usage_count, ak.owner_id,
         u.email as owner_email, u.company_name
  FROM api_keys ak
  JOIN users u ON ak.owner_id = u.id
  WHERE ak.id = ? AND ak.status = 'active' AND (ak.owner_id = ? OR ? = 'admin')
\`;

const keyResult = await db.query(keyQuery, [keyId, currentUserId, currentUserRole]);`,
      correct: true,
      explanation: `Correct! This implements proper authorization by restricting API key access to the owner or admin users. By adding the owner_id constraint to the WHERE clause, we ensure users can only access API keys they created. The admin exception allows for necessary administrative oversight while preventing horizontal privilege escalation where users could access other users' API keys and potentially gain access to their systems and data.`
    },
    // Real MITRE demonstrative examples as wrong answers
    {
      code: `const keyResult = await db.query(keyQuery, [keyId]);`,
      correct: false,
      explanation: 'Direct from MITRE CWE-639: Missing authorization allows users to access any API key by manipulating the key ID parameter. Attackers can enumerate key IDs to discover and access API keys belonging to other users, potentially gaining unauthorized access to their systems and data.'
    },
    {
      code: `if (keyId.includes('test')) { return res.status(403).json({ error: 'Test keys protected' }); }
const keyResult = await db.query(keyQuery, [keyId]);`,
      correct: false,
      explanation: 'Keyword filtering provides minimal protection. While it may block API keys containing "test", users can still access any production API key by manipulating the key ID, gaining unauthorized access to other users\' API credentials.'
    },
    {
      code: `const keyHash = crypto.createHash('md5').update(keyId).digest('hex');
const keyResult = await db.query('SELECT * FROM api_keys WHERE MD5(id) = ?', [keyHash]);`,
      correct: false,
      explanation: 'Hashing the key ID does not solve the authorization problem. This only obfuscates the lookup method but does not verify ownership - users can still access any API key by providing the correct key ID.'
    },
    {
      code: `if (req.headers['x-api-version'] !== '2.0') { return res.status(400).json({ error: 'API version required' }); }
const keyResult = await db.query(keyQuery, [keyId]);`,
      correct: false,
      explanation: 'API versioning does not implement object-level authorization. Even with the correct version header, users can still access any API key by manipulating the key ID parameter.'
    },
    {
      code: `const currentHour = new Date().getHours();
if (currentHour < 8 || currentHour > 18) { return res.status(403).json({ error: 'API access outside business hours' }); }
const keyResult = await db.query(keyQuery, [keyId]);`,
      correct: false,
      explanation: 'Time-based access control does not prevent unauthorized key access. While this may enforce business hours, users can still access other users\' API keys during allowed hours by manipulating the key ID.'
    },
    {
      code: `const userSubscription = await getUserSubscription(req.user.id);
if (userSubscription !== 'enterprise') { return res.status(403).json({ error: 'Enterprise feature' }); }
const keyResult = await db.query(keyQuery, [keyId]);`,
      correct: false,
      explanation: 'Subscription-based feature gating does not provide key-level authorization. While this restricts the feature to enterprise users, any enterprise user can still access any API key regardless of ownership.'
    },
    {
      code: `await logApiKeyAccess(req.user.id, keyId);
const keyResult = await db.query(keyQuery, [keyId]);`,
      correct: false,
      explanation: 'Audit logging does not prevent unauthorized access. While logging is valuable for detection and forensics, this does not stop users from accessing API keys that belong to other users.'
    },
    {
      code: `const rateLimitKey = \`apikey_\${req.user.id}\`;
if (await rateLimiter.isExceeded(rateLimitKey)) { return res.status(429).json({ error: 'Rate limit exceeded' }); }
const keyResult = await db.query(keyQuery, [keyId]);`,
      correct: false,
      explanation: 'Rate limiting does not prevent unauthorized key access, only limits the frequency. Users can still access other users\' API keys within the rate limit boundaries, just at a slower pace.'
    },
    {
      code: `if (keyId.length !== 16) { return res.status(400).json({ error: 'Invalid key length' }); }
const keyResult = await db.query(keyQuery, [keyId]);`,
      correct: false,
      explanation: 'Length validation only checks format compliance. While this ensures the key ID meets expected format requirements, it does not verify whether the requesting user has permission to access that specific API key.'
    }
  ]
}