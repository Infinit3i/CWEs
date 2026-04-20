import type { Exercise } from '@/data/exercises'

/**
 * CWE-22 exercise - User Profile Access
 * Based on MITRE demonstrative examples for path traversal in web applications
 */
export const cwe22ProfileAccess: Exercise = {
  cweId: 'CWE-22',
  name: 'Path Traversal - User Profile Access',
  language: 'Python',

  vulnerableFunction: `function getUserProfile(username) {
  const profilePath = '/var/www/profiles/' + username + '.json';

  try {
    const profileData = fs.readFileSync(profilePath, 'utf8');
    return JSON.parse(profileData);
  } catch (error) {
    return null;
  }
}`,

  vulnerableLine: `const profilePath = '/var/www/profiles/' + username + '.json';`,

  options: [
    {
      code: `const safeName = username.replace(/[^a-zA-Z0-9_-]/g, ''); if (!safeName || safeName !== username) throw new Error('Invalid username'); const profilePath = path.resolve('/var/www/profiles/' + safeName + '.json');`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    {
      code: `const profilePath = '/users/cwe/profiles/' + username + '.json';`,
      correct: false,
      explanation: 'This pattern enables attackers to inject "../../../etc/passwd%00" to escape the intended directory and access sensitive files, with null byte truncation bypassing the .json extension.'
    },
    {
      code: `const cleaned = username.replace('../', ''); const profilePath = '/var/www/profiles/' + cleaned + '.json';`,
      correct: false,
      explanation: 'MITRE vulnerability: Regular expressions that remove only the first instance of "../" fail when attackers provide multiple sequences - after one instance is stripped, traversal sequences remain.'
    },
    {
      code: `if (username.startsWith('user_')) { const profilePath = '/var/www/profiles/' + username + '.json'; }`,
      correct: false,
      explanation: 'startsWith() validation can be bypassed. Input like "user_../../etc/passwd" passes validation yet still contains effective traversal sequences.'
    },
    {
      code: `const profilePath = path.join('/var/www/profiles', username + '.json');`,
      correct: false,
      explanation: 'MITRE example: path.join() discards the base directory when provided an absolute path, allowing attackers to supply "/etc/passwd" to completely bypass directory restrictions.'
    },
    {
      code: `const escaped = username.replace(/\\/g, ''); const profilePath = '/var/www/profiles/' + escaped + '.json';`,
      correct: false,
      explanation: 'Filtering only backslashes is insufficient on Unix systems where forward slashes are the primary directory separator for traversal attacks.'
    },
    {
      code: `const trimmed = username.substring(0, 20); const profilePath = '/var/www/profiles/' + trimmed + '.json';`,
      correct: false,
      explanation: 'Length truncation does not prevent path traversal. Sequences like "../../../etc/passwd" remain effective even when shortened.'
    },
    {
      code: `if (!username.includes('..')) { const profilePath = '/var/www/profiles/' + username + '.json'; }`,
      correct: false,
      explanation: 'Checking for literal ".." misses encoded variants like "%2e%2e", Unicode bypasses, or alternative traversal methods like absolute paths.'
    },
    {
      code: `const normalized = username.normalize(); const profilePath = '/var/www/profiles/' + normalized + '.json';`,
      correct: false,
      explanation: 'Unicode normalization alone does not prevent path traversal attacks using standard ASCII characters like "../".'
    },
    {
      code: `const base64 = Buffer.from(username, 'base64').toString(); const profilePath = '/var/www/profiles/' + base64 + '.json';`,
      correct: false,
      explanation: 'Base64 decoding without validation creates additional attack surface by potentially revealing traversal sequences hidden in encoded input.'
    }
  ]
}