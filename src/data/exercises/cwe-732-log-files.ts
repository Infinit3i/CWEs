import type { Exercise } from '@/data/exercises'

export const cwe732LogFiles: Exercise = {
  cweId: 'CWE-732',
  name: 'Incorrect Permission Assignment - Application Logging',

  vulnerableFunction: `function initializeLogging(logLevel) {
  const fs = require('fs');
  const logPath = '/var/log/myapp/application.log';

  // Ensure log directory exists
  fs.mkdirSync('/var/log/myapp', { recursive: true, mode: 0o755 });

  // Create or update log file permissions
  if (fs.existsSync(logPath)) {
    fs.chmodSync(logPath, 0o666);
  }

  const logStream = fs.createWriteStream(logPath, { flags: 'a', mode: 0o666 });
  return logStream;
}`,

  vulnerableLine: `fs.chmodSync(logPath, 0o666);`,

  options: [
    {
      code: `fs.chmodSync(logPath, 0o640);`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    {
      code: `fs.chmodSync(logPath, 0o666);`,
      correct: false,
      explanation: 'Mode 0o666 creates world-writable log files. Any user can read sensitive application data or inject false log entries.'
    },
    {
      code: `fs.chmodSync(logPath, 0o777);`,
      correct: false,
      explanation: 'Mode 0o777 is extremely dangerous for log files. From MITRE examples of world-writable logs enabling privilege escalation and log poisoning.'
    },
    {
      code: `fs.chmodSync(logPath, 0o644);`,
      correct: false,
      explanation: 'Mode 0o644 makes logs readable by all users. Application logs often contain sensitive data like user IDs, IP addresses, and error details.'
    },
    {
      code: `fs.chmodSync(logPath, 0o600);`,
      correct: false,
      explanation: 'While secure, mode 0o600 prevents legitimate log monitoring tools and administrators from accessing logs for troubleshooting and analysis.'
    },
    {
      code: `fs.chmodSync(logPath, 0o622);`,
      correct: false,
      explanation: 'Mode 0o622 allows others to write to the log file. Attackers could inject malicious entries or corrupt audit trails.'
    },
    {
      code: `fs.chmodSync(logPath, 0o664);`,
      correct: false,
      explanation: 'Mode 0o664 makes logs readable by all users. Similar to 0o644, this exposes potentially sensitive application information.'
    },
    {
      code: `fs.chmodSync(logPath, 0o660);`,
      correct: false,
      explanation: 'Mode 0o660 allows group members to write to logs. Depending on group membership, this could enable log tampering by unauthorized users.'
    }
  ]
}