import type { Exercise } from '@/data/exercises'

/**
 * CWE-642: External Control of Critical State Data - File Path Manipulation
 * Based on MITRE file path example where critical path data is client-controlled
 */
export const cwe642FilePathControl: Exercise = {
  cweId: 'CWE-642',
  name: 'External Control of Critical State Data - File Access Control',

  vulnerableFunction: `function deleteReportFile(request) {
  const reportName = request.body.reportName;
  const userDirectory = request.body.userDirectory;

  // Construct file path from client data
  const filePath = \`/app/reports/\${userDirectory}/\${reportName}\`;

  // Check if file exists
  if (!fs.existsSync(filePath)) {
    return { error: 'Report not found' };
  }

  // Validate user directory ownership
  if (userDirectory !== request.user.directory) {
    return { error: 'Unauthorized access' };
  }

  // Delete the file
  fs.unlinkSync(filePath);

  return { success: 'Report deleted successfully' };
}`,

  vulnerableLine: `const filePath = \`/app/reports/\${userDirectory}/\${reportName}\`;`,

  options: [
    {
      code: `const sanitizedDirectory = path.basename(userDirectory); const sanitizedReport = path.basename(reportName); const filePath = path.join('/app/reports', sanitizedDirectory, sanitizedReport);`,
      correct: true,
      explanation: `Correct! Uses path.basename() to prevent directory traversal and path.join() for safe construction. This prevents attackers from using ../../../ sequences to access files outside intended directories.`
    },
    {
      code: `const filePath = \`/app/reports/\${userDirectory}/\${reportName}\`; // Direct concatenation`,
      correct: false,
      explanation: 'Direct MITRE vulnerability pattern. Allows directory traversal where reportName="../../../etc/passwd" can access system files outside the reports directory, causing unauthorized file deletion.'
    },
    {
      code: `const cleanDirectory = userDirectory.replace(/\\.\\./g, ''); const filePath = \`/app/reports/\${cleanDirectory}/\${reportName}\`;`,
      correct: false,
      explanation: 'Simple filtering is bypassable. Attackers can use encoded sequences like %2e%2e%2f or nested patterns like ....//.. to circumvent basic string replacement filtering.'
    },
    {
      code: `const filePath = userDirectory.startsWith('/') ? \`\${userDirectory}/\${reportName}\` : \`/app/reports/\${userDirectory}/\${reportName}\`;`,
      correct: false,
      explanation: 'Absolute path detection but still vulnerable. Relative traversal attacks like "user/../../../etc/passwd" can still access unauthorized files within the conditional logic.'
    },
    {
      code: `const encodedDirectory = encodeURIComponent(userDirectory); const filePath = \`/app/reports/\${encodedDirectory}/\${reportName}\`;`,
      correct: false,
      explanation: 'URL encoding doesn\'t prevent directory traversal. The file system will decode the path, and attackers can provide pre-encoded traversal sequences or rely on application decoding.'
    },
    {
      code: `const limitedDirectory = userDirectory.substring(0, 50); const filePath = \`/app/reports/\${limitedDirectory}/\${reportName}\`;`,
      correct: false,
      explanation: 'Length limiting doesn\'t address traversal attacks. Short sequences like "../../../etc/passwd" fit within 50 characters and can still access unauthorized system files.'
    },
    {
      code: `const normalizedDirectory = userDirectory.toLowerCase(); const filePath = \`/app/reports/\${normalizedDirectory}/\${reportName}\`;`,
      correct: false,
      explanation: 'Case normalization doesn\'t prevent directory traversal. Lowercase "../../../etc/passwd" sequences remain functional for accessing files outside intended directories.'
    },
    {
      code: `if (userDirectory.includes('..')) throw new Error('Invalid directory'); const filePath = \`/app/reports/\${userDirectory}/\${reportName}\`;`,
      correct: false,
      explanation: 'Basic detection but incomplete protection. Attackers can use absolute paths, encoded sequences, or symlink attacks that don\'t contain literal ".." strings.'
    },
    {
      code: `const hashedDirectory = crypto.createHash('md5').update(userDirectory).digest('hex'); const filePath = \`/app/reports/\${hashedDirectory}/\${reportName}\`;`,
      correct: false,
      explanation: 'Hashing the directory name prevents traversal but breaks legitimate functionality. Users cannot access their actual directories if directory names are hashed rather than validated.'
    },
    {
      code: `const whitelistedChars = /^[a-zA-Z0-9_-]+$/; if (!whitelistedChars.test(userDirectory)) throw new Error('Invalid chars'); const filePath = \`/app/reports/\${userDirectory}/\${reportName}\`;`,
      correct: false,
      explanation: 'Character allowlist for directory is good but reportName remains unvalidated. Attackers can still use directory traversal in the reportName parameter to access unauthorized files.'
    }
  ]
}