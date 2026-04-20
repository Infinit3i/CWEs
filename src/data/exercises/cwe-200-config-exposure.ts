import type { Exercise } from '@/data/exercises'

/**
 * CWE-200: Information Exposure Through Configuration Files
 * Scenario: Web server serving configuration files with sensitive data
 * Based on MITRE patterns for unintended file exposure
 */
export const cwe200ConfigExposure: Exercise = {
  cweId: 'CWE-200',
  name: 'Information Exposure - Configuration File Access',
  language: 'Java',

  vulnerableFunction: `app.get('/config/:filename', (req, res) => {
  try {
    const filename = req.params.filename;
    
    // Validate filename format
    if (!/^[a-zA-Z0-9._-]+$/.test(filename)) {
      return res.status(400).json({ error: 'Invalid filename format' });
    }
    
    // Construct file path
    const configPath = path.join(__dirname, 'config', filename);
    
    // Check if file exists
    if (!fs.existsSync(configPath)) {
      return res.status(404).json({ error: 'Configuration file not found' });
    }
    
    // Read and return configuration file
    const configContent = fs.readFileSync(configPath, 'utf8');
    
    // Parse JSON if applicable
    let parsedContent;
    try {
      parsedContent = JSON.parse(configContent);
    } catch (e) {
      parsedContent = configContent;
    }
    
    res.json({
      filename: filename,
      content: parsedContent,
      lastModified: fs.statSync(configPath).mtime,
      size: fs.statSync(configPath).size
    });
    
  } catch (error) {
    res.status(500).json({
      error: 'Failed to read configuration',
      details: error.message,
      path: error.path
    });
  }
});`,

  vulnerableLine: `const configPath = path.join(__dirname, 'config', filename);`,

  options: [
    {
      code: `// Implement allowlist of safe configuration files
const allowedConfigs = ['app-settings.json', 'ui-config.json', 'feature-flags.json'];

if (!allowedConfigs.includes(filename)) {
  return res.status(403).json({ error: 'Configuration file access denied' });
}

// Additional check for admin access for sensitive configs
if (['app-settings.json'].includes(filename) && req.user?.role !== 'admin') {
  return res.status(403).json({ error: 'Admin access required' });
}

const configPath = path.join(__dirname, 'config', 'public', filename);`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    // Real MITRE demonstrative examples as wrong answers
    {
      code: `const configPath = path.join(__dirname, 'config', filename);`,
      correct: false,
      explanation: 'Direct from MITRE CWE-200: Unrestricted file access allows attackers to retrieve sensitive configuration files containing database passwords, API keys, encryption secrets, and system architecture details by manipulating the filename parameter.'
    },
    {
      code: `if (filename.includes('secret') || filename.includes('password')) {
  return res.status(403).json({ error: 'Restricted file' });
}
const configPath = path.join(__dirname, 'config', filename);`,
      correct: false,
      explanation: 'Keyword blacklisting from MITRE examples is easily bypassed. Attackers can access files like "database.json", "keys.json", or ".env" that contain sensitive information but do not include the blacklisted keywords.'
    },
    {
      code: `const safePath = filename.replace(/[^a-zA-Z0-9.-]/g, '');
const configPath = path.join(__dirname, 'config', safePath);`,
      correct: false,
      explanation: 'Character filtering does not prevent access to sensitive files. Legitimate config files like "database.json" or "prod.env" contain only allowed characters but may expose credentials and sensitive system information.'
    },
    {
      code: `if (filename.startsWith('.')) {
  return res.status(403).json({ error: 'Hidden files not accessible' });
}
const configPath = path.join(__dirname, 'config', filename);`,
      correct: false,
      explanation: 'Dot file filtering only blocks hidden files but allows access to regular configuration files that often contain sensitive information like "config.json", "database.yml", or "settings.ini".'
    },
    {
      code: `if (path.extname(filename) !== '.json') {
  return res.status(400).json({ error: 'Only JSON files allowed' });
}
const configPath = path.join(__dirname, 'config', filename);`,
      correct: false,
      explanation: 'Extension filtering provides minimal protection. JSON configuration files like "database.json", "secrets.json", or "production.json" can contain highly sensitive credentials and system information.'
    },
    {
      code: `const fileSize = fs.statSync(path.join(__dirname, 'config', filename)).size;
if (fileSize > 10000) {
  return res.status(413).json({ error: 'File too large' });
}
const configPath = path.join(__dirname, 'config', filename);`,
      correct: false,
      explanation: 'File size restrictions do not prevent access to sensitive content. Small configuration files often contain the most critical information like database credentials, API keys, and encryption secrets.'
    },
    {
      code: `if (req.user && req.user.permissions.includes('config-read')) {
  const configPath = path.join(__dirname, 'config', filename);
} else {
  return res.status(403).json({ error: 'Permission required' });
}`,
      correct: false,
      explanation: 'Generic permission checking is insufficient without file-specific authorization. Users with config-read permissions can still access sensitive files they should not have access to, like database credentials.'
    },
    {
      code: `const configPath = path.join(__dirname, 'config', filename);
const content = fs.readFileSync(configPath, 'utf8').replace(/password.*$/gm, 'password: [REDACTED]');`,
      correct: false,
      explanation: 'Content filtering after file access still exposes the file\'s existence and structure. Simple regex patterns miss many sensitive data formats and may not catch all credential types.'
    },
    {
      code: `const timestamp = Date.now();
if (timestamp % 1000 < 500) {
  return res.status(503).json({ error: 'Service temporarily unavailable' });
}
const configPath = path.join(__dirname, 'config', filename);`,
      correct: false,
      explanation: 'Random availability does not provide security. Attackers can retry requests until successful and gain access to sensitive configuration files with credentials and system details.'
    }
  ]
}
