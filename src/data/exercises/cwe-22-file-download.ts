import type { Exercise } from '@/data/exercises'

/**
 * CWE-22 exercise - File Download Endpoint
 * Based on MITRE demonstrative examples for path traversal vulnerabilities
 */
export const cwe22FileDownload: Exercise = {
  cweId: 'CWE-22',
  name: 'Path Traversal - File Download Endpoint',

  vulnerableFunction: `app.get('/api/download/:filename', (req, res) => {
  const filename = req.params.filename;
  const filePath = path.join(__dirname, 'uploads', filename);

  if (fs.existsSync(filePath)) {
    res.download(filePath);
  } else {
    res.status(404).send('File not found');
  }
});`,

  vulnerableLine: `const filePath = path.join(__dirname, 'uploads', filename);`,

  options: [
    {
      code: `const safeName = path.basename(filename); const filePath = path.join(__dirname, 'uploads', safeName); const normalized = path.resolve(filePath); if (!normalized.startsWith(path.resolve(__dirname, 'uploads'))) throw new Error('Access denied');`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    {
      code: `const filePath = '/users/cwe/profiles/' + filename;`,
      correct: false,
      explanation: 'String concatenation with user input allows attackers to inject "../../../etc/passwd" to escape the intended directory and access sensitive files.'
    },
    {
      code: `const cleaned = filename.replace('../', ''); const filePath = path.join(__dirname, 'uploads', cleaned);`,
      correct: false,
      explanation: 'Removing only the first instance of "../" fails when attackers provide multiple sequences like "../../../etc/passwd" - after one is stripped, traversal sequences remain.'
    },
    {
      code: `if (filename.startsWith('/uploads/')) { const filePath = filename; }`,
      correct: false,
      explanation: 'MITRE vulnerability: startsWith() validation can be bypassed. A path like "/uploads/../important.dat" passes validation yet the "../" sequence still accesses files outside the directory.'
    },
    {
      code: `const filePath = path.join(__dirname, filename);`,
      correct: false,
      explanation: 'Path joining without base directory validation allows absolute paths. Attackers can supply "/etc/passwd" to bypass directory restrictions entirely.'
    },
    {
      code: `const filtered = filename.replace(/\.\./g, ''); const filePath = path.join(__dirname, 'uploads', filtered);`,
      correct: false,
      explanation: 'Simple regex filtering can be bypassed with encoded sequences like %2e%2e%2f or double-encoded paths that decode after validation.'
    },
    {
      code: `if (filename.includes('/')) { throw new Error('Invalid'); } const filePath = path.join(__dirname, 'uploads', filename);`,
      correct: false,
      explanation: 'Blocking forward slashes helps but is insufficient on Windows systems where backslashes (\\) can also traverse directories.'
    },
    {
      code: `const decoded = decodeURIComponent(filename); const filePath = path.join(__dirname, 'uploads', decoded);`,
      correct: false,
      explanation: 'URL decoding without validation actually increases attack surface by enabling encoded traversal sequences like %2e%2e%2f to become ../'
    },
    {
      code: `if (filename.length > 50) { throw new Error('Too long'); } const filePath = path.join(__dirname, 'uploads', filename);`,
      correct: false,
      explanation: 'Length validation alone is insufficient. Short traversal sequences like "../../../etc" can be very effective within length limits.'
    },
    {
      code: `const sanitized = filename.toLowerCase(); const filePath = path.join(__dirname, 'uploads', sanitized);`,
      correct: false,
      explanation: 'Case conversion does not prevent path traversal. Lowercase "../etc/passwd" sequences are still effective for directory escape.'
    }
  ]
}