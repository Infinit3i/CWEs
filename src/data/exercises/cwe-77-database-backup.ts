import type { Exercise } from '@/data/exercises'

/**
 * CWE-77 exercise: Database backup command injection
 * Based on database administration tools that execute system commands
 */
export const cwe77DatabaseBackup: Exercise = {
  cweId: 'CWE-77',
  name: 'Command Injection - Database Backup Utility',
  language: 'Go',

  vulnerableFunction: `function createDatabaseBackup(dbName, username, backupPath, compressionLevel) {
  const { exec } = require('child_process');

  // Validate compression level
  if (compressionLevel < 0 || compressionLevel > 9) {
    throw new Error('Invalid compression level');
  }

  // Build mysqldump command
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const backupFile = \`\${backupPath}/\${dbName}_\${timestamp}.sql\`;

  let cmd = \`mysqldump -u\${username} --single-transaction \${dbName} > \${backupFile}\`;

  // Add compression if requested
  if (compressionLevel > 0) {
    cmd = \`mysqldump -u\${username} --single-transaction \${dbName} | gzip -\${compressionLevel} > \${backupFile}.gz\`;
  }

  return new Promise((resolve, reject) => {
    exec(cmd, { env: { MYSQL_PWD: process.env.MYSQL_PASSWORD } }, (error, stdout, stderr) => {
      if (error) {
        reject(\`Backup failed: \${error.message}\`);
        return;
      }

      resolve({
        success: true,
        database: dbName,
        backupFile: compressionLevel > 0 ? \`\${backupFile}.gz\` : backupFile,
        compressed: compressionLevel > 0
      });
    });
  });
}`,

  vulnerableLine: `let cmd = \`mysqldump -u\${username} --single-transaction \${dbName} > \${backupFile}\`;`,

  options: [
    {
      code: `function createDatabaseBackup(dbName, username, backupPath, compressionLevel) {
  const { spawn } = require('child_process');
  const path = require('path');
  const fs = require('fs');

  // Validate inputs
  if (!/^[a-zA-Z0-9_]+$/.test(dbName)) {
    throw new Error('Invalid database name');
  }
  if (!/^[a-zA-Z0-9_]+$/.test(username)) {
    throw new Error('Invalid username');
  }

  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const sanitizedPath = path.resolve(backupPath);
  const backupFile = path.join(sanitizedPath, \`\${dbName}_\${timestamp}.sql\`);

  return new Promise((resolve, reject) => {
    const mysqldump = spawn('mysqldump', [
      \`-u\${username}\`,
      '--single-transaction',
      dbName
    ], {
      env: { MYSQL_PWD: process.env.MYSQL_PASSWORD },
      stdio: ['ignore', 'pipe', 'pipe']
    });

    const writeStream = fs.createWriteStream(backupFile);
    mysqldump.stdout.pipe(writeStream);

    mysqldump.on('close', (code) => {
      if (code === 0) {
        resolve({ success: true, backupFile: backupFile });
      } else {
        reject('Backup failed');
      }
    });
  });
}`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    // Database backup command injection vulnerabilities
    {
      code: `let cmd = \`mysqldump -u\${username} --single-transaction \${dbName} > \${backupFile}\`;
exec(cmd);`,
      correct: false,
      explanation: 'Multiple unvalidated parameters in mysqldump command. Database names like "test; drop database prod;" or usernames with injection can execute arbitrary SQL or shell commands.'
    },
    {
      code: `cmd = \`mysqldump -u\${username} --single-transaction \${dbName} | gzip -\${compressionLevel} > \${backupFile}.gz\`;
exec(cmd);`,
      correct: false,
      explanation: 'Complex pipeline with multiple injection points. Compression levels, database names, and file paths can all contain shell metacharacters that alter command execution.'
    },
    {
      code: `const cmd = \`pg_dump -U \${username} -h \${hostname} \${dbName} -f \${backupFile}\`;
exec(cmd);`,
      correct: false,
      explanation: 'PostgreSQL dump command with multiple unsanitized parameters. Hostnames, usernames, and database names can contain injection payloads that execute arbitrary commands.'
    },
    {
      code: `const cmd = \`sqlite3 \${dbPath} ".dump" | gzip > \${backupFile}\`;
exec(cmd);`,
      correct: false,
      explanation: 'SQLite backup with file path injection. Database paths containing shell metacharacters can break out of the sqlite3 command and execute arbitrary code.'
    },
    {
      code: `if (dbName.length < 50) {
    const cmd = \`mysqldump \${dbName} > backup.sql\`;
    exec(cmd);
}`,
      correct: false,
      explanation: 'Length validation does not prevent command injection. Short payloads like "db;id" can execute commands within the length restriction.'
    },
    {
      code: `const safeDbName = dbName.replace(/['"]/g, '');
const cmd = \`mysqldump "\${safeDbName}" > backup.sql\`;
exec(cmd);`,
      correct: false,
      explanation: 'Quote removal is insufficient protection. Other shell metacharacters like backticks, semicolons, and command substitution can still inject commands.'
    },
    {
      code: `const cmd = \`mysqldump --defaults-file=\${configFile} \${dbName}\`;
exec(cmd);`,
      correct: false,
      explanation: 'Configuration file parameters create additional injection vectors. Malicious config file paths can point to attacker-controlled files or contain shell metacharacters.'
    },
    {
      code: `const cmd = util.format('mysqldump -u%s %s > %s', username, dbName, backupFile);
exec(cmd);`,
      correct: false,
      explanation: 'String formatting does not sanitize shell metacharacters. All parameters can still contain injection payloads that execute during command execution.'
    },
    {
      code: `const encodedDb = Buffer.from(dbName).toString('base64');
const cmd = \`echo \${encodedDb} | base64 -d | xargs mysqldump\`;
exec(cmd);`,
      correct: false,
      explanation: 'Base64 encoding with xargs creates complex injection opportunities. The overall command structure can be manipulated through encoding bypasses or xargs behavior.'
    },
    {
      code: `if (/^[a-zA-Z0-9_]+$/.test(dbName)) {
    const cmd = \`mysqldump \${dbName} --where="\${whereClause}"\`;
    exec(cmd);
}`,
      correct: false,
      explanation: 'Database name validation is good, but the WHERE clause parameter is unvalidated. SQL injection in the where clause can be combined with command injection.'
    }
  ]
}