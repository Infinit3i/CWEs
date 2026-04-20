import type { Exercise } from '@/data/exercises'

/**
 * CWE-200: Information Exposure Through Debug Endpoints
 * Scenario: Debug endpoint exposing system and user information
 * Based on MITRE patterns for development feature information leakage
 */
export const cwe200DebugEndpoint: Exercise = {
  cweId: 'CWE-200',
  name: 'Information Exposure - Debug Endpoint',

  vulnerableFunction: `app.get('/debug/system-info', async (req, res) => {
  // System debugging endpoint for development
  try {
    const systemInfo = {
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      cpu: process.cpuUsage(),
      platform: os.platform(),
      arch: os.arch(),
      hostname: os.hostname(),
      versions: process.versions,
      environment: {
        nodeEnv: process.env.NODE_ENV,
        port: process.env.PORT,
        dbHost: process.env.DB_HOST,
        dbUser: process.env.DB_USER,
        dbPassword: process.env.DB_PASSWORD,
        jwtSecret: process.env.JWT_SECRET,
        awsAccessKey: process.env.AWS_ACCESS_KEY_ID,
        awsSecret: process.env.AWS_SECRET_ACCESS_KEY
      },
      activeConnections: await db.query('SELECT COUNT(*) as count FROM user_sessions'),
      lastUsers: await db.query('SELECT id, email, password_hash, ssn FROM users ORDER BY created_at DESC LIMIT 5'),
      systemLogs: await readFileSync('/var/log/app.log', 'utf8').split('\\n').slice(-20)
    };

    res.json({
      status: 'System Debug Information',
      data: systemInfo,
      generatedAt: Date.now()
    });

  } catch (error) {
    res.status(500).json({
      error: 'Debug info generation failed',
      details: error.message,
      stack: error.stack
    });
  }
});`,

  vulnerableLine: `res.json({`,

  options: [
    {
      code: `// Check if user has admin privileges and environment allows debug
if (req.user?.role !== 'admin') {
  return res.status(403).json({ error: 'Admin access required' });
}

if (process.env.NODE_ENV === 'production') {
  return res.status(404).json({ error: 'Endpoint not available' });
}

// Return limited, safe system info only
const safeInfo = {
  timestamp: new Date().toISOString(),
  uptime: Math.floor(process.uptime()),
  status: 'healthy',
  version: process.env.APP_VERSION || 'unknown'
};

res.json(safeInfo);`,
      correct: true,
      explanation: `Correct! This implements proper access control and environment restrictions for debug endpoints. By requiring admin privileges and disabling the endpoint in production, we prevent unauthorized access to sensitive system information. The safe response includes only basic operational data without exposing credentials, user data, or system internals that could be used for attacks.`
    },
    // Real MITRE demonstrative examples as wrong answers
    {
      code: `res.json({
  status: 'System Debug Information',
  data: systemInfo,
  generatedAt: Date.now()
});`,
      correct: false,
      explanation: 'Direct from MITRE CWE-200: Unrestricted debug endpoints expose sensitive system information including database credentials, API keys, user data with passwords/SSNs, and system architecture details that enable targeted attacks and credential theft.'
    },
    {
      code: `// Remove password from environment before sending
delete systemInfo.environment.dbPassword;
delete systemInfo.environment.jwtSecret;
res.json({ status: 'Debug Info', data: systemInfo });`,
      correct: false,
      explanation: 'Partial redaction from MITRE examples is insufficient. The response still exposes database hosts, usernames, AWS keys, user emails, password hashes, SSNs, and system logs containing sensitive operational data.'
    },
    {
      code: `if (req.query.secret !== 'debug123') {
  return res.status(403).json({ error: 'Invalid debug key' });
}
res.json({ status: 'Debug Info', data: systemInfo });`,
      correct: false,
      explanation: 'Hardcoded secret authentication is weak security. Attackers can discover the secret through source code access, traffic analysis, or brute force, then gain access to all sensitive system information.'
    },
    {
      code: `const maskedInfo = JSON.parse(JSON.stringify(systemInfo));
maskedInfo.environment.dbPassword = '***';
maskedInfo.environment.jwtSecret = '***';
res.json({ status: 'Debug Info', data: maskedInfo });`,
      correct: false,
      explanation: 'Simple masking does not address the scope of information exposure. Database hosts, AWS credentials, user data with hashes and SSNs, and system logs remain exposed for attackers to exploit.'
    },
    {
      code: `if (req.ip !== '127.0.0.1') {
  return res.status(403).json({ error: 'Localhost access only' });
}
res.json({ status: 'Debug Info', data: systemInfo });`,
      correct: false,
      explanation: 'IP restriction is easily bypassed through proxy headers, VPN connections, or server compromise. Local access still exposes all sensitive data to anyone with server access or header manipulation capabilities.'
    },
    {
      code: `const currentTime = new Date().getHours();
if (currentTime < 9 || currentTime > 17) {
  return res.status(403).json({ error: 'Debug available during business hours only' });
}
res.json({ status: 'Debug Info', data: systemInfo });`,
      correct: false,
      explanation: 'Time-based restrictions do not provide real security. Attackers can simply wait for business hours or manipulate system time to access the sensitive information during allowed periods.'
    },
    {
      code: `const requestCount = await getRequestCount(req.ip);
if (requestCount > 5) {
  return res.status(429).json({ error: 'Rate limit exceeded' });
}
res.json({ status: 'Debug Info', data: systemInfo });`,
      correct: false,
      explanation: 'Rate limiting does not prevent information exposure, only limits frequency. Attackers can still access sensitive system data, credentials, and user information within the rate limit boundaries.'
    },
    {
      code: `const randomChance = Math.random();
if (randomChance < 0.5) {
  return res.status(503).json({ error: 'Debug temporarily unavailable' });
}
res.json({ status: 'Debug Info', data: systemInfo });`,
      correct: false,
      explanation: 'Random availability is not a security control. Attackers can retry requests until they get lucky and gain access to all the sensitive system information and credentials.'
    },
    {
      code: `console.log('Debug endpoint accessed by:', req.ip);
res.json({ status: 'Debug Info', data: systemInfo });`,
      correct: false,
      explanation: 'Logging access does not prevent information exposure. While audit trails are useful for detection, this does not stop attackers from accessing sensitive data, credentials, and user information.'
    }
  ]
}
