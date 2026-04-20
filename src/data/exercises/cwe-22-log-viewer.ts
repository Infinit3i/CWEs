import type { Exercise } from '@/data/exercises'

/**
 * CWE-22 exercise - Log File Viewer
 * Based on MITRE demonstrative examples for path traversal in file viewing applications
 */
export const cwe22LogViewer: Exercise = {
  cweId: 'CWE-22',
  name: 'Path Traversal - Log File Viewer',

  vulnerableFunction: `app.get('/admin/logs/:logfile', authenticateAdmin, (req, res) => {
  const logFile = req.params.logfile;
  const logPath = path.join('/var/log/app/', logFile);

  try {
    const logContent = fs.readFileSync(logPath, 'utf8');
    res.json({ content: logContent.split('\\n').slice(-100) });
  } catch (error) {
    res.status(404).json({ error: 'Log file not found' });
  }
});`,

  vulnerableLine: `const logPath = path.join('/var/log/app/', logFile);`,

  options: [
    {
      code: `const safeName = path.basename(logFile); const logPath = path.resolve('/var/log/app/', safeName); const expectedPrefix = path.resolve('/var/log/app/'); if (!logPath.startsWith(expectedPrefix + '/') && logPath !== expectedPrefix) throw new Error('Access denied');`,
      correct: true,
      explanation: `Correct! This solution uses basename() to strip directories, resolves the full path, then validates it stays within /var/log/app/. The boundary check prevents any form of directory escape while still allowing legitimate log files.`
    },
    {
      code: `const logPath = '/users/cwe/profiles/' + logFile;`,
      correct: false,
      explanation: 'Direct from MITRE: This concatenation allows attackers to inject "../../../etc/passwd" to escape the intended log directory and access sensitive system files.'
    },
    {
      code: `const filtered = logFile.replace('../', ''); const logPath = path.join('/var/log/app/', filtered);`,
      correct: false,
      explanation: 'MITRE pattern: Removing only the first "../" fails against attacks like "../../../etc/passwd" where multiple traversal sequences exist.'
    },
    {
      code: `if (logFile.startsWith('app_')) { const logPath = path.join('/var/log/app/', logFile); }`,
      correct: false,
      explanation: 'MITRE vulnerability: Prefix checks can be bypassed with "app_../../../etc/passwd" that starts correctly but contains traversal sequences.'
    },
    {
      code: `const logPath = path.join('/var/log/app/', logFile);`,
      correct: false,
      explanation: 'MITRE example: path.join() discards the base when given absolute paths, so "/etc/passwd" becomes "/etc/passwd" instead of "/var/log/app/etc/passwd".'
    },
    {
      code: `const escaped = logFile.replace(/[/\\\\]/g, '_'); const logPath = path.join('/var/log/app/', escaped);`,
      correct: false,
      explanation: 'Replacing path separators with underscores prevents some traversal but may break legitimate log file names and could be bypassed with encoded sequences.'
    },
    {
      code: `if (logFile.endsWith('.log')) { const logPath = path.join('/var/log/app/', logFile); }`,
      correct: false,
      explanation: 'File extension validation helps but does not prevent traversal. "../../../etc/passwd.log" would pass this check yet still escape the directory.'
    },
    {
      code: `const decoded = Buffer.from(logFile, 'base64').toString(); const logPath = path.join('/var/log/app/', decoded);`,
      correct: false,
      explanation: 'Base64 decoding without validation creates additional attack vectors by potentially revealing traversal sequences in encoded input.'
    },
    {
      code: `const truncated = logFile.substring(0, 30); const logPath = path.join('/var/log/app/', truncated);`,
      correct: false,
      explanation: 'Length truncation does not prevent traversal attacks. Short sequences like "../../passwd" can be very effective within length limits.'
    },
    {
      code: `const clean = logFile.split('..').join('.'); const logPath = path.join('/var/log/app/', clean);`,
      correct: false,
      explanation: 'Replacing ".." with "." may create new attack vectors and does not address encoded traversal sequences or absolute path attacks.'
    }
  ]
}