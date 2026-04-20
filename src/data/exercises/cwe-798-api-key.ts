import type { Exercise } from '@/data/exercises'

/**
 * CWE-798: Hard-coded API Key in Microservice Configuration
 * Enterprise scenario: API gateway with embedded third-party service credentials
 */
export const cwe798ApiKey: Exercise = {
  cweId: 'CWE-798',
  name: 'Hard-coded Credentials - API Gateway Configuration',

  vulnerableFunction: `class PaymentGateway {
  constructor(private config: any) {}

  async processPayment(amount: number, cardToken: string) {
    const apiKey = "pk_live_51HvJ2eK8mGtD9X4Y7Wz3QpR6vN8Mc2UdF9sG4Hj";
    const endpoint = "https://api.stripe.com/v1/charges";

    return fetch(endpoint, {
      method: 'POST',
      headers: {
        'Authorization': \`Bearer \${apiKey}\`,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams({ amount: amount.toString(), source: cardToken })
    });
  }
}`,

  vulnerableLine: `const apiKey = "pk_live_51HvJ2eK8mGtD9X4Y7Wz3QpR6vN8Mc2UdF9sG4Hj";`,

  options: [
    {
      code: `const apiKey = process.env.STRIPE_API_KEY || (() => { throw new Error('STRIPE_API_KEY environment variable is required'); })();`,
      correct: true,
      explanation: `Store credentials in environment variables`
    },
    {
      code: `const apiKey = "pk_live_51HvJ2eK8mGtD9X4Y7Wz3QpR6vN8Mc2UdF9sG4Hj";`,
      correct: false,
      explanation: 'Hard-coded production API keys in source code are exposed to anyone with repository access. Bytecode decompilation or source inspection reveals credentials immediately.'
    },
    {
      code: `const apiKey = Buffer.from("cGtfbGl2ZV81MUh2SjJlSzhtR3REOVg0WTdXejNRcFI2dk44TWMyVWRGOXNHNEhq", "base64").toString();`,
      correct: false,
      explanation: 'Base64 encoding is not encryption. The credential is still embedded in source code and trivially decoded by attackers.'
    },
    {
      code: `const apiKey = this.config.stripeKey || "pk_test_fallback_key_12345";`,
      correct: false,
      explanation: 'Fallback credentials in source code create the same vulnerability. Even test keys can provide unauthorized access to development environments.'
    },
    {
      code: `const apiKey = await this.decryptApiKey("U2FsdGVkX1+vupppZksvRf5pq5g5XjFRIipRkwB0K1Y=");`,
      correct: false,
      explanation: 'Encrypted strings in source code are vulnerable if the decryption key is also embedded. Without proper key management, this provides false security.'
    },
    {
      code: `const apiKey = localStorage.getItem('stripe_api_key') || 'default_key';`,
      correct: false,
      explanation: 'Client-side storage of API keys exposes them in browser developer tools. Server-side credentials should never be accessible to client code.'
    },
    {
      code: `const apiKey = require('../config/keys.json').stripe.production;`,
      correct: false,
      explanation: 'Configuration files containing credentials are still source code vulnerabilities. JSON files with secrets get committed to version control.'
    },
    {
      code: `const apiKey = process.env.NODE_ENV === 'production' ? 'pk_live_51HvJ2eK...' : 'pk_test_12345';`,
      correct: false,
      explanation: 'Environment-based conditionals with embedded credentials still expose production keys in source code, violating secure secret management.'
    }
  ]
}