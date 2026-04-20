import type { Exercise } from '@/data/exercises'

/**
 * CWE-276 Incorrect Default Permissions - Directory Creation
 * Based on MITRE CVE examples of world-readable directories
 */
export const cwe276Directory: Exercise = {
  cweId: 'CWE-276',
  name: 'Incorrect Default Permissions - User Data Directory',
  language: 'C',

  vulnerableFunction: `function setupUserDirectory(username) {
  const userDir = \`/home/users/\${username}\`;
  const privateDir = \`\${userDir}/private\`;
  const documentsDir = \`\${userDir}/documents\`;

  // Create user directory structure
  fs.mkdirSync(userDir, { recursive: true });
  fs.mkdirSync(privateDir, { recursive: true });
  fs.mkdirSync(documentsDir, { recursive: true });

  return {
    success: true,
    directories: [userDir, privateDir, documentsDir],
    message: 'User directory structure created'
  };
}`,

  vulnerableLine: `fs.mkdirSync(userDir, { recursive: true });`,

  options: [
    {
      code: `const userDir = \`/home/users/\${username}\`;
fs.mkdirSync(userDir, { recursive: true, mode: 0o700 }); // Owner only
fs.mkdirSync(\`\${userDir}/private\`, { mode: 0o700 });   // Owner only
fs.mkdirSync(\`\${userDir}/documents\`, { mode: 0o755 }); // Owner write, others read
return { success: true, directories: [userDir] };`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    // MITRE CVE-inspired wrong answers
    {
      code: `fs.mkdirSync(userDir, { recursive: true });
fs.mkdirSync(privateDir, { recursive: true });
fs.mkdirSync(documentsDir, { recursive: true });`,
      correct: false,
      explanation: 'Based on MITRE CVE-2002-1711: Creating directories with default permissions often results in world-readable directories (755), allowing any user to list and potentially access private user files.'
    },
    {
      code: `fs.mkdirSync(userDir, { recursive: true, mode: 0o777 });
fs.mkdirSync(privateDir, { recursive: true, mode: 0o777 });
fs.mkdirSync(documentsDir, { recursive: true, mode: 0o777 });`,
      correct: false,
      explanation: 'Extremely dangerous: 777 permissions allow any user to read, write, and execute in these directories. Users could access, modify, or delete other users\' private files and inject malicious content.'
    },
    {
      code: `fs.mkdirSync(userDir, { recursive: true, mode: 0o666 });
fs.mkdirSync(privateDir, { recursive: true, mode: 0o666 });`,
      correct: false,
      explanation: 'World-writable directories (666) allow any user to create, modify, or delete files in user directories. This could lead to data tampering, file injection attacks, or denial of service.'
    },
    {
      code: `fs.mkdirSync(userDir, { recursive: true, mode: 0o755 });
fs.mkdirSync(privateDir, { recursive: true, mode: 0o755 });`,
      correct: false,
      explanation: 'While 755 is appropriate for public directories, using it for private directories allows other users to list and potentially access private files. Private directories should use 700 (owner-only access).'
    },
    {
      code: `// Create with default permissions then fix later
fs.mkdirSync(userDir, { recursive: true });
fs.chmodSync(userDir, 0o700);
fs.mkdirSync(privateDir, { recursive: true });
fs.chmodSync(privateDir, 0o700);`,
      correct: false,
      explanation: 'Race condition vulnerability: directories exist with insecure default permissions before chmod is called. During this window, other users could access or list directory contents.'
    },
    {
      code: `fs.mkdirSync(userDir, { recursive: true, mode: 0o644 });
fs.mkdirSync(privateDir, { recursive: true, mode: 0o644 });`,
      correct: false,
      explanation: 'Permissions 644 are inappropriate for directories. While not writable by others, these permissions may not allow proper directory traversal and could cause functionality issues while still exposing directory listings.'
    },
    {
      code: `const oldUmask = process.umask(0o000); // Remove umask restrictions
fs.mkdirSync(userDir, { recursive: true });
fs.mkdirSync(privateDir, { recursive: true });
process.umask(oldUmask);`,
      correct: false,
      explanation: 'Removing umask restrictions (setting to 000) allows maximum permissions. Combined with default directory creation, this could create world-writable directories, leading to security vulnerabilities.'
    },
    {
      code: `fs.mkdirSync(userDir, { recursive: true, mode: 0o722 });
fs.mkdirSync(privateDir, { recursive: true, mode: 0o722 });`,
      correct: false,
      explanation: 'Permissions 722 allow group and world users to write to the directory but not read it. This creates an inconsistent security model and could allow file injection attacks by users who cannot see existing files.'
    },
    {
      code: `fs.mkdirSync(userDir, { recursive: true, mode: 0o744 });
fs.mkdirSync(privateDir, { recursive: true, mode: 0o744 });`,
      correct: false,
      explanation: 'While 744 prevents others from writing, it still allows world-read access to directory listings. Private directories should use 700 to prevent any access by other users to maintain confidentiality.'
    }
  ]
}