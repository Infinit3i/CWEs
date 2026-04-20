import type { Exercise } from '@/data/exercises'

/**
 * CWE-798: Hard-coded JWT Signing Secret in Authentication Service
 * Enterprise scenario: Microservice authentication with embedded cryptographic secret
 */
export const cwe798JwtSecret: Exercise = {
  cweId: 'CWE-798',
  name: 'Hard-coded Credentials - JWT Signing Secret',

  vulnerableFunction: `class AuthenticationService {
  private jwtSecret = "myCompanySecretKey2024!ForJWTSigning";

  generateToken(userId: string, permissions: string[]) {
    const payload = {
      sub: userId,
      permissions: permissions,
      iss: 'company-auth-service',
      exp: Math.floor(Date.now() / 1000) + (60 * 60 * 24) // 24 hours
    };

    return jwt.sign(payload, this.jwtSecret, { algorithm: 'HS256' });
  }

  verifyToken(token: string) {
    try {
      return jwt.verify(token, this.jwtSecret, { algorithm: 'HS256' });
    } catch (error) {
      throw new Error('Invalid token');
    }
  }
}`,

  vulnerableLine: `private jwtSecret = "myCompanySecretKey2024!ForJWTSigning";`,

  options: [
    {
      code: `private jwtSecret = process.env.JWT_SIGNING_SECRET;`,
      correct: true,
      explanation: `Correct! JWT signing secrets must be kept out of source code. Environment variables allow secure injection without exposing cryptographic material that could compromise all tokens across the entire system.`
    },
    {
      code: `private jwtSecret = "myCompanySecretKey2024!ForJWTSigning";`,
      correct: false,
      explanation: 'From MITRE: Hard-coded cryptographic keys in source code allow attackers to forge authentication tokens. Anyone with code access can sign valid JWTs for any user.'
    },
    {
      code: `private jwtSecret = Buffer.from("bXlDb21wYW55U2VjcmV0S2V5MjAyNCFGb3JKV1RTaWduaW5n", "base64").toString();`,
      correct: false,
      explanation: 'Base64 encoding provides no cryptographic protection. The JWT secret remains embedded in source code and easily decoded for token forgery attacks.'
    },
    {
      code: `private jwtSecret = crypto.createHash('sha256').update('myCompanySecretKey2024').digest('hex');`,
      correct: false,
      explanation: 'Hashing predictable input strings still embeds the secret generation method in source code, allowing attackers to reproduce the signing key.'
    },
    {
      code: `private jwtSecret = process.env.APP_NAME + "_secret_" + new Date().getFullYear();`,
      correct: false,
      explanation: 'Algorithmic secret generation using predictable environment variables and dates creates guessable signing keys while embedding the algorithm in source.'
    },
    {
      code: `private jwtSecret = require('../config/jwt-config.json').signingKey;`,
      correct: false,
      explanation: 'Configuration files containing cryptographic secrets are still source code vulnerabilities. JSON files with signing keys get committed to version control.'
    },
    {
      code: `private jwtSecret = this.loadSecretFromFile('/app/secrets/jwt.key');`,
      correct: false,
      explanation: 'Reading secrets from static files within the application deployment couples cryptographic keys to source code distribution and deployment paths.'
    },
    {
      code: `private jwtSecret = process.env.NODE_ENV === 'production' ? 'prodSecret123!' : 'devSecret456!';`,
      correct: false,
      explanation: 'Environment-conditional embedded secrets still expose production cryptographic keys in source code, compromising token security across environments.'
    }
  ]
}