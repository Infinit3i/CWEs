import type { Exercise } from '@/data/exercises'

/**
 * CWE-276 Incorrect Default Permissions - Cryptographic Keys
 * Based on MITRE CVE examples of insecure key file permissions
 */
export const cwe276Key: Exercise = {
  cweId: 'CWE-276',
  name: 'Incorrect Default Permissions - SSL Certificate Storage',

  vulnerableFunction: `function installSSLCertificate(certData, keyData) {
  const certDir = '/etc/ssl/certs';
  const keyDir = '/etc/ssl/private';
  const certPath = path.join(certDir, 'server.crt');
  const keyPath = path.join(keyDir, 'server.key');

  // Create directories and install certificate files
  fs.mkdirSync(certDir, { recursive: true });
  fs.mkdirSync(keyDir, { recursive: true });

  fs.writeFileSync(certPath, certData);
  fs.writeFileSync(keyPath, keyData);

  return {
    success: true,
    certificate: certPath,
    privateKey: keyPath,
    message: 'SSL certificate installed'
  };
}`,

  vulnerableLine: `fs.writeFileSync(keyPath, keyData);`,

  options: [
    {
      code: `fs.mkdirSync(certDir, { recursive: true, mode: 0o755 });
fs.mkdirSync(keyDir, { recursive: true, mode: 0o700 }); // Private key dir restricted
fs.writeFileSync(certPath, certData, { mode: 0o644 }); // Public cert readable
fs.writeFileSync(keyPath, keyData, { mode: 0o600 });   // Private key owner-only
// Verify critical permissions
if ((fs.statSync(keyPath).mode & parseInt('777', 8)) !== parseInt('600', 8)) {
  throw new Error('Private key permissions not secure');
}`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    // MITRE CVE-inspired wrong answers
    {
      code: `fs.writeFileSync(certPath, certData);
fs.writeFileSync(keyPath, keyData);`,
      correct: false,
      explanation: 'Based on MITRE CVE-2001-0497: Installing cryptographic keys with default permissions often results in world-readable private keys, allowing any user to decrypt SSL traffic or impersonate the server.'
    },
    {
      code: `fs.writeFileSync(certPath, certData, { mode: 0o644 });
fs.writeFileSync(keyPath, keyData, { mode: 0o644 });`,
      correct: false,
      explanation: 'World-readable private keys (644) completely compromise SSL security. Any user can read the private key and decrypt all SSL communications or create fraudulent certificates for man-in-the-middle attacks.'
    },
    {
      code: `fs.writeFileSync(certPath, certData, { mode: 0o666 });
fs.writeFileSync(keyPath, keyData, { mode: 0o666 });`,
      correct: false,
      explanation: 'World-writable cryptographic files (666) are extremely dangerous. Attackers can read private keys for decryption attacks and modify certificates to redirect traffic to malicious servers.'
    },
    {
      code: `fs.writeFileSync(certPath, certData, { mode: 0o755 });
fs.writeFileSync(keyPath, keyData, { mode: 0o755 });`,
      correct: false,
      explanation: 'Executable permissions are unnecessary for certificate files and 755 makes private keys world-readable. This exposes the private key while potentially enabling unexpected execution behavior.'
    },
    {
      code: `fs.writeFileSync(keyPath, keyData, { mode: 0o640 });`,
      correct: false,
      explanation: 'Group-readable private keys (640) allow any member of the file\'s group to read the private key. This could enable SSL traffic decryption and certificate forgery by unauthorized group members.'
    },
    {
      code: `// Install files then secure private key
fs.writeFileSync(certPath, certData);
fs.writeFileSync(keyPath, keyData);
fs.chmodSync(keyPath, 0o600);`,
      correct: false,
      explanation: 'Race condition: the private key exists with default (potentially world-readable) permissions before chmod secures it. Attackers could read the private key during this critical window.'
    },
    {
      code: `fs.mkdirSync(keyDir, { recursive: true, mode: 0o755 });
fs.writeFileSync(keyPath, keyData, { mode: 0o600 });`,
      correct: false,
      explanation: 'While the private key file has secure permissions, the containing directory (755) allows other users to list directory contents, potentially revealing key file names and facilitating targeted attacks.'
    },
    {
      code: `const oldUmask = process.umask(0o000);
fs.writeFileSync(keyPath, keyData);
process.umask(oldUmask);`,
      correct: false,
      explanation: 'Removing umask restrictions (000) combined with default file creation typically results in world-readable or even world-writable private keys, completely compromising cryptographic security.'
    },
    {
      code: `fs.writeFileSync(keyPath, keyData, { mode: 0o622 });`,
      correct: false,
      explanation: 'Permissions 622 make private keys world-readable and group-writable. This allows any user to read the key for decryption attacks and group members to modify the key, potentially creating backdoors.'
    }
  ]
}