import type { Exercise } from '@/data/exercises'

export const cwe732ConfigFiles: Exercise = {
  cweId: 'CWE-732',
  name: 'Incorrect Permission Assignment - Configuration File Security',

  vulnerableFunction: `function deployConfiguration(config) {
  const fs = require('fs');
  const configPath = '/etc/myapp/database.conf';

  const configContent = \`
host=\${config.dbHost}
username=\${config.dbUser}
password=\${config.dbPassword}
ssl_key=\${config.sslKeyPath}
\`;

  fs.writeFileSync(configPath, configContent);

  // Update permissions for service account access
  fs.chmodSync(configPath, 0o644);

  return configPath;
}`,

  vulnerableLine: `fs.chmodSync(configPath, 0o644);`,

  options: [
    {
      code: `fs.chmodSync(configPath, 0o600);`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    {
      code: `fs.chmodSync(configPath, 0o644);`,
      correct: false,
      explanation: 'Mode 0o644 allows all users to read the configuration file containing database passwords and SSL keys. This is a critical credential exposure.'
    },
    {
      code: `fs.chmodSync(configPath, 0o755);`,
      correct: false,
      explanation: 'Mode 0o755 makes the configuration readable by everyone and executable. Configuration files should not be executable and contain sensitive credentials.'
    },
    {
      code: `fs.chmodSync(configPath, 0o666);`,
      correct: false,
      explanation: 'Mode 0o666 allows any user to read or modify the configuration. From MITRE examples of world-writable config files enabling privilege escalation.'
    },
    {
      code: `fs.chmodSync(configPath, 0o640);`,
      correct: false,
      explanation: 'Mode 0o640 allows group members to read database credentials. Unless the group specifically needs access, this violates principle of least privilege.'
    },
    {
      code: `fs.chmodSync(configPath, 0o664);`,
      correct: false,
      explanation: 'Mode 0o664 allows group and others to read sensitive credentials. Similar to MITRE examples of overly permissive configuration files.'
    },
    {
      code: `fs.chmodSync(configPath, 0o622);`,
      correct: false,
      explanation: 'Mode 0o622 allows others to modify the configuration. Attackers could change database connections to redirect data or inject malicious settings.'
    },
    {
      code: `fs.chmodSync(configPath, 0o660);`,
      correct: false,
      explanation: 'Mode 0o660 allows group write access to credentials. Group members could modify database connections or steal authentication data.'
    }
  ]
}