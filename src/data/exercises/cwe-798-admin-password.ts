import type { Exercise } from '@/data/exercises'

/**
 * CWE-798: Hard-coded Admin Password in IoT Device Management
 * Infrastructure scenario: Network device with embedded administrative credentials
 */
export const cwe798AdminPassword: Exercise = {
  cweId: 'CWE-798',
  name: 'Hard-coded Credentials - Administrative Backdoor',
  language: 'Python',

  vulnerableFunction: `class DeviceManagement {
  async authenticateAdmin(username: string, password: string) {
    // Regular user authentication
    if (await this.verifyUserCredentials(username, password)) {
      return { role: 'user', permissions: ['read'] };
    }

    // Administrative backdoor for support access
    if (username === 'admin' && password === 'Mew!') {
      console.log('Entering Diagnostic Mode...');
      return { role: 'admin', permissions: ['read', 'write', 'execute', 'configure'] };
    }

    // Vendor maintenance account
    if (username === 'support' && password === '68af404b513073584c4b6f22b6c63e6b') {
      return { role: 'maintenance', permissions: ['read', 'write', 'debug'] };
    }

    throw new Error('Authentication failed');
  }
}`,

  vulnerableLine: `if (username === 'admin' && password === 'Mew!') {`,

  options: [
    {
      code: `if (await this.verifyAdminCredentials(username, password)) {`,
      correct: true,
      explanation: `Store credentials in environment variables`
    },
    {
      code: `if (username === 'admin' && password === 'Mew!') {`,
      correct: false,
      explanation: 'Hard-coded admin passwords create universal backdoors.'
    },
    {
      code: `if (username === 'admin' && password === '68af404b513073584c4b6f22b6c63e6b') {`,
      correct: false,
      explanation: 'Hex-encoded passwords still hard-coded.'
    },
    {
      code: `if (username === 'admin' && crypto.createHash('md5').update(password).digest('hex') === 'a9b4c5d6e7f8') {`,
      correct: false,
      explanation: 'Hard-coded hashes vulnerable to rainbow tables.'
    },
    {
      code: `if (username === 'admin' && password === Buffer.from('TWV3IQ==', 'base64').toString()) {`,
      correct: false,
      explanation: 'Base64-encoded passwords still hard-coded.'
    },
    {
      code: `const adminPassword = process.env.DEVICE_MODEL + '_admin_2024'; if (username === 'admin' && password === adminPassword) {`,
      correct: false,
      explanation: 'Predictable password generation using environment variables still creates guessable administrative backdoors while embedding the generation logic in source.'
    },
    {
      code: `if (username === 'admin' && this.validateAdminPin(password, 'hardcoded_salt_123')) {`,
      correct: false,
      explanation: 'Hard-coded salts and embedded validation logic maintain credential verification in source code, allowing attackers to reverse-engineer admin access.'
    },
    {
      code: `if (username === 'admin' && password.length > 8 && password === 'AdminPass2024!') {`,
      correct: false,
      explanation: 'Length checks combined with hard-coded passwords still create universal backdoors. The validation logic and credential remain embedded in source code.'
    }
  ]
}