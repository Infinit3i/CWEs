import type { Exercise } from '@/data/exercises'

/**
 * CWE-276 Incorrect Default Permissions - Configuration Files
 * Based on MITRE CVE examples of world-readable password files
 */
export const cwe276Config: Exercise = {
  cweId: 'CWE-276',
  name: 'Incorrect Default Permissions - Database Configuration',

  vulnerableFunction: `function saveDbConfig(configData) {
  const configPath = '/etc/myapp/database.conf';
  const configContent = \`
[database]
host=\${configData.host}
username=\${configData.username}
password=\${configData.password}
encryption_key=\${configData.encryptionKey}
  \`;

  fs.mkdirSync(path.dirname(configPath), { recursive: true });
  fs.writeFileSync(configPath, configContent);

  return {
    success: true,
    configPath: configPath,
    message: 'Database configuration saved'
  };
}`,

  vulnerableLine: `fs.writeFileSync(configPath, configContent);`,

  options: [
    {
      code: `fs.mkdirSync(path.dirname(configPath), { recursive: true, mode: 0o755 });
fs.writeFileSync(configPath, configContent, { mode: 0o600 });
// Verify permissions were set correctly
const stats = fs.statSync(configPath);
if ((stats.mode & parseInt('777', 8)) !== parseInt('600', 8)) {
  throw new Error('Failed to set secure permissions');
}`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    // MITRE CVE-inspired wrong answers
    {
      code: `fs.mkdirSync(path.dirname(configPath), { recursive: true });
fs.writeFileSync(configPath, configContent);`,
      correct: false,
      explanation: 'Based on MITRE CVE-2001-1550: Configuration files with default permissions often become world-readable, exposing database credentials, encryption keys, and other sensitive information to any user on the system.'
    },
    {
      code: `fs.writeFileSync(configPath, configContent, { mode: 0o644 });`,
      correct: false,
      explanation: 'Permissions 644 make the config file world-readable. Any user can read database passwords and encryption keys, leading to complete system compromise through credential exposure.'
    },
    {
      code: `fs.writeFileSync(configPath, configContent, { mode: 0o666 });`,
      correct: false,
      explanation: 'Based on MITRE CVE patterns: 666 permissions make config files world-writable. Attackers can modify database credentials, change connection strings to rogue servers, or inject malicious configuration.'
    },
    {
      code: `fs.writeFileSync(configPath, configContent, { mode: 0o755 });`,
      correct: false,
      explanation: 'Executable permissions on config files are unnecessary and dangerous. 755 also makes the file world-readable, exposing sensitive credentials while the execute bit could enable unexpected behavior.'
    },
    {
      code: `fs.writeFileSync(configPath, configContent, { mode: 0o777 });`,
      correct: false,
      explanation: 'Maximum permissions (777) are extremely dangerous for config files. Any user can read sensitive credentials and modify the configuration, potentially redirecting the application to malicious databases.'
    },
    {
      code: `// Create file then secure it
fs.writeFileSync(configPath, configContent);
fs.chmodSync(configPath, 0o600);`,
      correct: false,
      explanation: 'Race condition vulnerability: the config file with sensitive credentials exists with default (potentially world-readable) permissions before chmod secures it. Attackers could read credentials during this window.'
    },
    {
      code: `fs.writeFileSync(configPath, configContent, { mode: 0o640 });`,
      correct: false,
      explanation: 'Group-readable permissions (640) allow any member of the file\'s group to read database credentials and encryption keys. This violates the principle of least privilege for highly sensitive data.'
    },
    {
      code: `const oldUmask = process.umask(0o000);
fs.writeFileSync(configPath, configContent);
process.umask(oldUmask);`,
      correct: false,
      explanation: 'Removing umask restrictions creates files with maximum default permissions. For sensitive config files, this typically results in world-readable files containing credentials and encryption keys.'
    },
    {
      code: `fs.writeFileSync(configPath, configContent, { mode: 0o622 });`,
      correct: false,
      explanation: 'Group-write and world-read permissions (622) allow group members to modify configuration and all users to read credentials. This combines the risks of credential exposure and configuration tampering.'
    }
  ]
}