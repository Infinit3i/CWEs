import type { Exercise } from '@/data/exercises'

/**
 * CWE-798: Hard-coded SSH Private Key in CI/CD Pipeline
 * DevOps scenario: Automated deployment script with embedded credentials
 */
export const cwe798SshKey: Exercise = {
  cweId: 'CWE-798',
  name: 'Hard-coded Credentials - SSH Deployment Key',
  language: 'Python',

  vulnerableFunction: `class DeploymentManager {
  async deployToProduction(artifacts: string[]) {
    const sshPrivateKey = \`-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA2+5L8f9K7x3Q8mZ4w2N1pR6vS4yE3uF8kL9mV2sA7bC5dE6f
G3hI8jK9lM0nO1pQ2rS3tU4vW5xY6zA7bC8dE9fG0hI1jK2lM3nO4pQ5rS6tU7vW
8xY9zA0bC1dE2fG3hI4jK5lM6nO7pQ8rS9tU0vW1xY2zA3bC4dE5fG6hI7jK8lM9n
O0pQ1rS2tU3vW4xY5zA6bC7dE8fG9hI0jK1lM2nO3pQ4rS5tU6vW7xY8zA9bC0dE
1fG2hI3jK4lM5nO6pQ7rS8tU9vW0xY1zA2bC3dE4fG5hI6jK7lM8nO9pQ0rS1tU2v
W3xY4zA5bC6dE7fG8hI9jK0lM1nO2pQ3rS4tU5vW6xY7zA8bC9dE0fG1hI2jK3lM4n
-----END RSA PRIVATE KEY-----\`;

    const connection = new SSH2.Client();
    await connection.connect({
      host: 'prod-server-01.company.com',
      username: 'deploy',
  language: 'Python',
      privateKey: sshPrivateKey
    });

    for (const artifact of artifacts) {
      await connection.exec(\`sudo systemctl stop app && cp \${artifact} /opt/app/\`);
    }
  }
}`,

  vulnerableLine: `const sshPrivateKey = \`-----BEGIN RSA PRIVATE KEY-----`,

  options: [
    {
      code: `const sshPrivateKey = process.env.SSH_PRIVATE_KEY?.replace(/\\\\n/g, '\\n');`,
      correct: true,
      explanation: `Store credentials in environment variables`
    },
    {
      code: `const sshPrivateKey = \`-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA2+5L8f9K7x3Q8mZ4w...\n-----END RSA PRIVATE KEY-----\`;`,
      correct: false,
      explanation: 'Embedding private cryptographic keys in source code exposes them to anyone with repository access. SSH keys provide direct server access and are high-value targets.'
    },
    {
      code: `const sshPrivateKey = atob('LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQ==');`,
      correct: false,
      explanation: 'Base64 encoding does not protect private keys. The credential remains embedded in source code and is trivially decoded by attackers.'
    },
    {
      code: `const sshPrivateKey = this.keyVault.decrypt('encrypted_ssh_key_v1');`,
      correct: false,
      explanation: 'Encrypted keys in source code are vulnerable when decryption logic and keys are also embedded. This creates complexity without solving the credential exposure problem.'
    },
    {
      code: `const sshPrivateKey = require('../secrets/deploy_key.pem');`,
      correct: false,
      explanation: 'Importing key files from the application bundle embeds secrets in deployable artifacts. Secret files become part of the distributed source code.'
    },
    {
      code: `const sshPrivateKey = fs.readFileSync('/opt/secrets/ssh_key', 'utf8');`,
      correct: false,
      explanation: 'While file-based secrets are better than embedded strings, hardcoded paths in application code still couple secrets to source code deployment locations.'
    },
    {
      code: `const sshPrivateKey = process.env.NODE_ENV === 'prod' ? productionKey : developmentKey;`,
      correct: false,
      explanation: 'Environment-conditional embedded keys still expose production credentials in source code, violating cryptographic key management principles.'
    },
    {
      code: `const sshPrivateKey = generateKeyFromSeed('company_deployment_2024');`,
      correct: false,
      explanation: 'Deterministic key generation with embedded seeds creates predictable credentials while keeping the generation algorithm in source code.'
    }
  ]
}