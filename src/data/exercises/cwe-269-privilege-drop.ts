import type { Exercise } from '@/data/exercises'

/**
 * CWE-269: Improper Privilege Management with Exception Handling
 * Infrastructure scenario: Privileged operation with improper privilege cleanup
 */
export const cwe269PrivilegeDrop: Exercise = {
  cweId: 'CWE-269',
  name: 'Privilege Management - Privilege Drop Failure',
  language: 'C',

  vulnerableFunction: `class SecureFileProcessor {
  private elevated = false;

  async processSecureFile(filePath: string, userId: string) {
    const user = await User.findById(userId);

    if (!user || !user.permissions.includes('process_secure_files')) {
      throw new Error('Insufficient permissions');
    }

    try {
      // Elevate privileges for file operations
      await this.elevatePrivileges();
      this.elevated = true;

      console.log('Processing secure file with elevated privileges');

      // Read secure file
      const content = await fs.promises.readFile(filePath, 'utf8');

      // Validate file format
      if (!this.validateSecureFormat(content)) {
        throw new Error('Invalid secure file format');
      }

      // Process file content
      const processedData = await this.processContent(content);

      // Write to secure output location
      const outputPath = '/secure/processed/' + path.basename(filePath);
      await fs.promises.writeFile(outputPath, processedData, { mode: 0o600 });

      // Drop privileges
      await this.dropPrivileges();
      this.elevated = false;

      return { success: true, outputPath };

    } catch (error) {
      console.error('File processing failed:', error.message);
      throw error;
    }
  }

  private async elevatePrivileges() {
    // Simulate privilege elevation
    process.setuid(0);
  }

  private async dropPrivileges() {
    // Simulate privilege drop
    process.setuid(1000);
  }
}`,

  vulnerableLine: `throw new Error('Invalid secure file format');`,

  options: [
    {
      code: `await this.dropPrivileges(); this.elevated = false; throw new Error('Invalid secure file format');`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    {
      code: `throw new Error('Invalid secure file format');`,
      correct: false,
      explanation: '"If os.mkdir() throws an exception, lowerPrivileges() never executes, leaving the program indefinitely in raised privilege state." Same issue - exceptions bypass privilege cleanup.'
    },
    {
      code: `console.error('Format validation failed'); throw new Error('Invalid secure file format');`,
      correct: false,
      explanation: 'Adding error logging does not address privilege cleanup. The elevated privileges remain active when the exception is thrown, creating a privilege management vulnerability.'
    },
    {
      code: `await new Promise(resolve => setTimeout(resolve, 100)); throw new Error('Invalid secure file format');`,
      correct: false,
      explanation: 'Adding delays before throwing exceptions does not drop privileges. The process remains in elevated state, and delays may actually worsen the privilege exposure window.'
    },
    {
      code: `this.elevated = false; throw new Error('Invalid secure file format');`,
      correct: false,
      explanation: 'Setting the flag without actually dropping privileges creates false security. The process remains elevated while the application believes privileges have been dropped.'
    },
    {
      code: `if (this.elevated) { console.log('Still elevated during error'); } throw new Error('Invalid secure file format');`,
      correct: false,
      explanation: 'Logging privilege state does not address the cleanup issue. The privileges remain elevated, and detection without remediation does not prevent the security vulnerability.'
    },
    {
      code: `process.nextTick(() => this.dropPrivileges()); throw new Error('Invalid secure file format');`,
      correct: false,
      explanation: 'Asynchronous privilege dropping after throwing an exception may not execute. The exception terminates the current execution path before the nextTick callback runs.'
    },
    {
      code: `const errorTime = Date.now(); throw new Error('Invalid secure file format at ' + errorTime);`,
      correct: false,
      explanation: 'Timestamping errors does not address privilege cleanup. The elevated privileges remain active when the exception occurs, maintaining the privilege management vulnerability.'
    }
  ]
}