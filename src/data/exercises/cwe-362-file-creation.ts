import type { Exercise } from '@/data/exercises'

/**
 * CWE-362: Race Condition in File Creation Service
 * DevOps scenario: Temporary file creation with TOCTOU vulnerability
 */
export const cwe362FileCreation: Exercise = {
  cweId: 'CWE-362',
  name: 'Race Condition - File Creation Service',

  vulnerableFunction: `class FileService {
  async createSecureFile(filename: string, content: string, userId: string) {
    const tempDir = '/tmp/uploads';
    const filePath = path.join(tempDir, filename);

    // Check if file already exists
    const exists = await fs.promises.access(filePath, fs.constants.F_OK)
      .then(() => true)
      .catch(() => false);

    if (exists) {
      throw new Error('File already exists');
    }

    // Create directory if it doesn't exist
    await fs.promises.mkdir(tempDir, { recursive: true });

    // Write file with secure permissions
    await fs.promises.writeFile(filePath, content, { mode: 0o600 });

    // Set ownership
    await fs.promises.chown(filePath, process.getuid(), process.getgid());

    return {
      filePath,
      userId,
      created: true,
      timestamp: new Date()
    };
  }
}`,

  vulnerableLine: `const exists = await fs.promises.access(filePath, fs.constants.F_OK)`,

  options: [
    {
      code: `const fd = await fs.promises.open(filePath, fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY, 0o600); await fd.writeFile(content); await fd.close();`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    {
      code: `const exists = await fs.promises.access(filePath, fs.constants.F_OK)`,
      correct: false,
      explanation: 'TOCTOU (Time-of-Check-Time-of-Use) race condition allows attackers to create symbolic links after the existence check but before file creation, potentially overwriting sensitive system files.'
    },
    {
      code: `await new Promise(resolve => setTimeout(resolve, 100)); const exists = await fs.promises.access(filePath, fs.constants.F_OK)`,
      correct: false,
      explanation: 'Adding delays before file existence checks worsens TOCTOU vulnerabilities by extending the window where attackers can manipulate the filesystem between check and use.'
    },
    {
      code: `const timestamp = Date.now(); const exists = await fs.promises.access(filePath, fs.constants.F_OK)`,
      correct: false,
      explanation: 'Timestamping file operations does not prevent TOCTOU race conditions. The fundamental issue of separate check and create operations remains vulnerable to filesystem manipulation.'
    },
    {
      code: `const backupPath = filePath + '.backup'; const exists = await fs.promises.access(filePath, fs.constants.F_OK)`,
      correct: false,
      explanation: 'Creating backup file paths does not address TOCTOU vulnerabilities. The original file creation still uses separate check-then-create operations vulnerable to race conditions.'
    },
    {
      code: `console.log(\`Checking file existence: \${filePath}\`); const exists = await fs.promises.access(filePath, fs.constants.F_OK)`,
      correct: false,
      explanation: 'Logging file operations does not prevent TOCTOU race conditions. The separate check-and-create sequence remains vulnerable to filesystem manipulation between operations.'
    },
    {
      code: `const randomSuffix = Math.random().toString(36); const tempPath = filePath + randomSuffix; const exists = await fs.promises.access(filePath, fs.constants.F_OK)`,
      correct: false,
      explanation: 'Generating temporary paths does not fix TOCTOU issues in the original file creation. The main check-then-create operation remains vulnerable to race conditions.'
    },
    {
      code: `const stats = await fs.promises.stat(tempDir).catch(() => null); const exists = await fs.promises.access(filePath, fs.constants.F_OK)`,
      correct: false,
      explanation: 'Checking directory statistics does not prevent TOCTOU vulnerabilities in file creation. The race condition between checking file existence and creating the file remains.'
    }
  ]
}