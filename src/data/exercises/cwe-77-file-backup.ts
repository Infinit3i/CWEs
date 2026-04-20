import type { Exercise } from '@/data/exercises'

/**
 * CWE-77 exercise: File backup command injection
 * Based on MITRE demonstrative examples showing OS command injection
 */
export const cwe77FileBackup: Exercise = {
  cweId: 'CWE-77',
  name: 'Command Injection - Automated File Backup System',

  vulnerableFunction: `function createFileBackup(fileName, backupType) {
  const { exec } = require('child_process');

  // Validate backup type
  const validTypes = ['daily', 'weekly', 'monthly'];
  if (!validTypes.includes(backupType)) {
    throw new Error('Invalid backup type');
  }

  // Create backup command
  const backupDir = '/var/backups/' + backupType;
  const cmd = \`tar -czf \${backupDir}/\${fileName}_backup.tar.gz \${fileName}\`;

  return new Promise((resolve, reject) => {
    exec(cmd, (error, stdout, stderr) => {
      if (error) {
        reject(\`Backup failed: \${error.message}\`);
        return;
      }

      resolve({
        success: true,
        backupFile: \`\${backupDir}/\${fileName}_backup.tar.gz\`,
        output: stdout
      });
    });
  });
}`,

  vulnerableLine: `const cmd = \`tar -czf \${backupDir}/\${fileName}_backup.tar.gz \${fileName}\`;`,

  options: [
    {
      code: `function createFileBackup(fileName, backupType) {
  const { spawn } = require('child_process');
  const path = require('path');

  const validTypes = ['daily', 'weekly', 'monthly'];
  if (!validTypes.includes(backupType)) {
    throw new Error('Invalid backup type');
  }

  // Validate and sanitize filename
  const sanitizedName = path.basename(fileName).replace(/[^a-zA-Z0-9._-]/g, '');
  if (!sanitizedName || sanitizedName !== path.basename(fileName)) {
    throw new Error('Invalid filename');
  }

  const backupDir = \`/var/backups/\${backupType}\`;
  const backupFile = \`\${sanitizedName}_backup.tar.gz\`;

  return new Promise((resolve, reject) => {
    const tar = spawn('tar', ['-czf', path.join(backupDir, backupFile), sanitizedName]);
    tar.on('close', (code) => {
      if (code === 0) {
        resolve({ success: true, backupFile: path.join(backupDir, backupFile) });
      } else {
        reject('Backup failed');
      }
    });
  });
}`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    // Command injection vulnerabilities from MITRE
    {
      code: `const cmd = \`tar -czf \${backupDir}/\${fileName}_backup.tar.gz \${fileName}\`;
exec(cmd);`,
      correct: false,
      explanation: 'Unescaped user input in shell commands. A filename like "test.txt; rm -rf /" would execute as "tar -czf backup.tar.gz test.txt; rm -rf /" destroying the file system.'
    },
    {
      code: `const cmd = '/bin/ls -l ' + fileName;
exec(cmd);`,
      correct: false,
      explanation: 'MITRE-style string concatenation allows command injection. Input like "-aR; cat /etc/passwd" produces "ls -l -aR; cat /etc/passwd" exposing system files.'
    },
    {
      code: `const cmd = \`cp \${fileName} \${backupDir}/\${fileName}.bak\`;
exec(cmd);`,
      correct: false,
      explanation: 'Template literals with unsanitized input enable injection. Filenames containing semicolons, pipes, or command substitution can execute arbitrary commands.'
    },
    {
      code: `const cmd = 'gzip -c ' + fileName + ' > ' + fileName + '.gz';
exec(cmd);`,
      correct: false,
      explanation: 'Multiple injection points in file operations. Both source and destination paths can contain malicious commands that execute during compression.'
    },
    {
      code: `if (fileName.includes('/')) {
    throw new Error('No path traversal');
}
const cmd = \`tar -czf backup.tar.gz \${fileName}\`;
exec(cmd);`,
      correct: false,
      explanation: 'Insufficient validation only checks for path traversal. Command injection characters like semicolons, pipes, and backticks are not filtered.'
    },
    {
      code: `const safeName = fileName.replace(/'/g, "\\\\'");
const cmd = \`tar -czf backup.tar.gz '\${safeName}'\`;
exec(cmd);`,
      correct: false,
      explanation: 'Quote escaping is incomplete and bypassable. Techniques like command substitution $(command) or backticks \`command\` can still execute within quotes.'
    },
    {
      code: `const cmd = \`find /data -name "\${fileName}" -exec cp {} /backup \\;\`;
exec(cmd);`,
      correct: false,
      explanation: 'Find command with user input allows injection. Malicious filenames can break out of the -name parameter and inject additional find expressions or commands.'
    },
    {
      code: `const encoded = Buffer.from(fileName).toString('base64');
const cmd = \`echo \${encoded} | base64 -d | tar -czf backup.tar.gz -T -\`;
exec(cmd);`,
      correct: false,
      explanation: 'Base64 encoding does not prevent command injection in complex pipelines. The overall command structure can still be manipulated through other parameters.'
    },
    {
      code: `if (fileName.length < 100) {
    const cmd = \`rsync -av \${fileName} backup/\`;
    exec(cmd);
}`,
      correct: false,
      explanation: 'Length validation does not prevent command injection. Short malicious payloads like "; id" can execute commands within the length limit.'
    },
    {
      code: `const cmd = util.format('tar -czf backup.tar.gz %s', fileName);
exec(cmd);`,
      correct: false,
      explanation: 'String formatting functions do not sanitize input for shell execution. The formatted string still contains unescaped user input that can inject commands.'
    }
  ]
}