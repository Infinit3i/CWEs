import type { Exercise } from '@/data/exercises'

/**
 * CWE-269: Improper Privilege Management in System Command Execution
 * Infrastructure scenario: DevOps tool with elevated command execution
 */
export const cwe269SystemCommand: Exercise = {
  cweId: 'CWE-269',
  name: 'Privilege Management - System Command Execution',

  vulnerableFunction: `class SystemManager {
  async executeSystemCommand(userId: string, command: string, sudo: boolean = false) {
    const user = await User.findById(userId);

    if (!user) {
      throw new Error('User not found');
    }

    // Basic privilege check
    if (user.role === 'guest') {
      throw new Error('Guests cannot execute system commands');
    }

    let fullCommand = command;

    // Elevate privileges if requested
    if (sudo) {
      if (user.role !== 'admin') {
        throw new Error('Only admins can use sudo');
      }
      fullCommand = \`sudo \${command}\`;
    }

    try {
      console.log(\`Executing command: \${fullCommand}\`);
      const result = await exec(fullCommand, { timeout: 30000 });

      await this.auditLogger.log('COMMAND_EXECUTED', {
        userId,
        command: fullCommand,
        exitCode: result.code || 0,
        timestamp: new Date()
      });

      return {
        success: true,
        output: result.stdout,
        error: result.stderr
      };
    } catch (error) {
      await this.auditLogger.log('COMMAND_FAILED', {
        userId,
        command: fullCommand,
        error: error.message
      });
      throw error;
    }
  }
}`,

  vulnerableLine: `if (user.role === 'guest') {`,

  options: [
    {
      code: `const allowedCommands = this.getAllowedCommands(user.role); if (!this.isCommandAllowed(command, allowedCommands)) { throw new Error('Command not authorized for user role'); }`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    {
      code: `if (user.role === 'guest') {`,
      correct: false,
      explanation: 'Overly permissive default case grants command execution to all non-guest users. This allows operators to run privileged commands they should not have access to, creating privilege escalation opportunities.'
    },
    {
      code: `const dangerousCommands = ['rm', 'mv', 'chmod', 'chown']; if (dangerousCommands.some(cmd => command.includes(cmd))) { throw new Error('Dangerous command blocked'); } if (user.role === 'guest') {`,
      correct: false,
      explanation: 'Blacklisting specific commands is insufficient. Many dangerous operations can be performed through allowed commands, and this approach misses command variations and parameters that can be harmful.'
    },
    {
      code: `if (user.role === 'guest' || (user.role === 'user' && sudo)) {`,
      correct: false,
      explanation: 'Preventing sudo for regular users is good but insufficient. The fundamental issue remains: users can still execute dangerous commands without sudo, and the privilege validation is incomplete.'
    },
    {
      code: `if (command.includes('sudo') || command.includes('su')) { throw new Error('Privilege escalation commands not allowed'); } if (user.role === 'guest') {`,
      correct: false,
      explanation: 'Blocking explicit privilege escalation commands misses many ways to gain elevated access. Commands can execute setuid binaries, modify configurations, or access sensitive files without using sudo/su.'
    },
    {
      code: `if (user.role === 'guest' || (!user.emailVerified && user.role !== 'admin')) {`,
      correct: false,
      explanation: 'Email verification requirements do not address privilege management. Unverified users can still execute dangerous commands if they have non-guest roles, maintaining the authorization vulnerability.'
    },
    {
      code: `const maxCommandLength = user.role === 'admin' ? 500 : 100; if (command.length > maxCommandLength) { throw new Error('Command too long'); } if (user.role === 'guest') {`,
      correct: false,
      explanation: 'Command length restrictions do not prevent privilege escalation. Short commands can still perform dangerous operations, and this approach does not address the content or authorization of commands.'
    },
    {
      code: `if (user.role === 'guest' || user.suspended) { throw new Error('User cannot execute commands'); }`,
      correct: false,
      explanation: 'Adding suspension checks improves account security but does not address the core privilege management issue. Active users can still execute commands beyond their authorization level.'
    }
  ]
}