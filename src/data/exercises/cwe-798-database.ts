import type { Exercise } from '@/data/exercises'

/**
 * CWE-798: Hard-coded Database Credentials in Enterprise Application
 * Infrastructure scenario: Microservice connecting to production database
 */
export const cwe798Database: Exercise = {
  cweId: 'CWE-798',
  name: 'Hard-coded Credentials - Database Connection Pool',
  language: 'Python',

  vulnerableFunction: `class DatabaseManager {
  private connectionPool: any;

  async initializeConnection() {
    const dbConfig = {
      host: 'prod-cluster.company.internal',
      port: 5432,
      database: 'customer_data',
      user: 'app_service',
      password: 'P@ssw0rd123!Company2024'
    };

    this.connectionPool = new Pool(dbConfig);
    return this.connectionPool.connect();
  }

  async getUserData(userId: string) {
    const client = await this.connectionPool.connect();
    const result = await client.query('SELECT * FROM users WHERE id = $1', [userId]);
    client.release();
    return result.rows[0];
  }
}`,

  vulnerableLine: `password: 'P@ssw0rd123!Company2024'`,

  options: [
    {
      code: `password: process.env.DB_PASSWORD`,
      correct: true,
      explanation: `Store credentials in environment variables`
    },
    {
      code: `password: 'P@ssw0rd123!Company2024'`,
      correct: false,
      explanation: '"Anyone who has access to it will have access to the password. Once the program has shipped, there is no going back from the database user unless the program is patched."'
    },
    {
      code: `password: Buffer.from('UEBzc3cwcmQxMjMhQ29tcGFueTIwMjQ=', 'base64').toString()`,
      correct: false,
      explanation: 'Base64 encoding provides no security. The password is still embedded in source code and easily decoded by anyone reading the application.'
    },
    {
      code: `password: this.decrypt('AES256:8f4c2a9b7e1d6c3a5b9e2f8c4d7a1b3e')`,
      correct: false,
      explanation: 'Encrypted passwords in code are vulnerable when decryption keys are also embedded. This creates false security while maintaining the core vulnerability.'
    },
    {
      code: `password: process.env.NODE_ENV === 'prod' ? 'prodPass123' : 'devPass123'`,
      correct: false,
      explanation: 'Environment conditionals with embedded passwords still expose production credentials in source code, violating secret management principles.'
    },
    {
      code: `password: require('fs').readFileSync('/app/db_secret.txt', 'utf8').trim()`,
      correct: false,
      explanation: 'Reading from static files within the application bundle embeds secrets in deployable artifacts. Secret files become part of the distributed code.'
    },
    {
      code: `password: new Date().getFullYear() + 'CompanyPassword'`,
      correct: false,
      explanation: 'Algorithmic password generation using predictable inputs creates guessable credentials while still embedding the algorithm in source code.'
    },
    {
      code: `password: this.config?.database?.password || 'default_db_password'`,
      correct: false,
      explanation: 'Default password fallbacks in source code create backdoor access when configuration fails, maintaining hard-coded credential vulnerabilities.'
    }
  ]
}