import type { Exercise } from '@/data/exercises'

/**
 * CWE-200: Information Exposure Through Backup File Access
 * Scenario: Web server inadvertently serving backup files with sensitive data
 * Based on MITRE patterns for unintended backup file exposure
 */
export const cwe200BackupExposure: Exercise = {
  cweId: 'CWE-200',
  name: 'Information Exposure - Backup File Access',

  vulnerableFunction: `app.get('/download/:filename', authenticateUser, (req, res) => {
  try {
    const filename = req.params.filename;
    
    // Basic filename validation
    if (!filename || filename.length > 255) {
      return res.status(400).json({ error: 'Invalid filename' });
    }
    
    // Sanitize filename to prevent path traversal
    const sanitized = filename.replace(/\\.\\./g, '').replace(/\\/+/g, '/');
    
    // Define download directory
    const downloadsDir = path.join(__dirname, 'public', 'downloads');
    const filePath = path.join(downloadsDir, sanitized);
    
    // Check if file exists
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ error: 'File not found' });
    }
    
    // Get file stats
    const stats = fs.statSync(filePath);
    const fileSize = stats.size;
    
    // Set headers for download
    res.setHeader('Content-Disposition', \`attachment; filename="\${path.basename(filePath)}"\`);
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Length', fileSize);
    
    // Stream file to client
    const fileStream = fs.createReadStream(filePath);
    
    fileStream.on('error', (err) => {
      console.error('File stream error:', err);
      if (!res.headersSent) {
        res.status(500).json({ error: 'Download failed' });
      }
    });
    
    fileStream.pipe(res);
    
  } catch (error) {
    console.error('Download error:', error);
    res.status(500).json({ 
      error: 'Download failed',
      details: error.message,
      path: error.path
    });
  }
});`,

  vulnerableLine: `const filePath = path.join(downloadsDir, sanitized);`,

  options: [
    {
      code: `// Implement strict allowlist for downloadable files
const allowedFiles = await db.query(
  'SELECT filename FROM user_files WHERE user_id = ? AND status = "approved"',
  [req.user.id]
);

const userFiles = allowedFiles.map(f => f.filename);
if (!userFiles.includes(sanitized)) {
  return res.status(403).json({ error: 'File access denied' });
}

// Additional check against backup file patterns
const backupPatterns = /\\.(bak|backup|old|tmp|~)$|\\_backup\\.|\\~$/;
if (backupPatterns.test(sanitized)) {
  return res.status(403).json({ error: 'Backup files not accessible' });
}

const filePath = path.join(downloadsDir, sanitized);`,
      correct: true,
      explanation: `Correct! This implements database-driven allowlisting to ensure users can only download files they own and that have been approved. The backup pattern filtering prevents access to common backup file extensions (.bak, .backup, .old, .tmp, ~) that often contain sensitive information. This prevents unauthorized access to system backups, database dumps, or configuration backups that may expose credentials and sensitive data.`
    },
    // Real MITRE demonstrative examples as wrong answers
    {
      code: `const filePath = path.join(downloadsDir, sanitized);`,
      correct: false,
      explanation: 'Direct from MITRE CWE-200: Unrestricted file access allows attackers to download backup files by guessing common backup naming patterns. Files like "database.sql.bak", "config.json.backup", or "users.csv~" often contain sensitive data including credentials, personal information, and system configurations.'
    },
    {
      code: `if (sanitized.includes('admin')) {
  return res.status(403).json({ error: 'Admin files protected' });
}
const filePath = path.join(downloadsDir, sanitized);`,
      correct: false,
      explanation: 'Keyword blacklisting from MITRE examples is insufficient. Attackers can access backup files like "database.bak", "config.old", "users.csv.backup", or "system.sql~" that contain sensitive information but do not include "admin" in the filename.'
    },
    {
      code: `const ext = path.extname(sanitized).toLowerCase();
const allowedExtensions = ['.pdf', '.jpg', '.png', '.txt'];
if (!allowedExtensions.includes(ext)) {
  return res.status(403).json({ error: 'File type not allowed' });
}
const filePath = path.join(downloadsDir, sanitized);`,
      correct: false,
      explanation: 'Extension allowlisting helps but misses backup files with allowed extensions. Attackers can access files like "users.txt.backup", "config.json.old", or backup files renamed with allowed extensions.'
    },
    {
      code: `if (fs.statSync(path.join(downloadsDir, sanitized)).size > 10000000) {
  return res.status(413).json({ error: 'File too large' });
}
const filePath = path.join(downloadsDir, sanitized);`,
      correct: false,
      explanation: 'File size restrictions do not prevent backup file access. Many critical backup files like configuration backups, user lists, or API key files are small but contain highly sensitive information.'
    },
    {
      code: `const createdTime = fs.statSync(path.join(downloadsDir, sanitized)).birthtime;
if (Date.now() - createdTime.getTime() > 86400000) {
  return res.status(403).json({ error: 'File too old' });
}
const filePath = path.join(downloadsDir, sanitized);`,
      correct: false,
      explanation: 'Age-based restrictions do not prevent access to recent backup files. Attackers can still access newly created backup files that may contain current sensitive data, credentials, or user information.'
    },
    {
      code: `const basename = path.basename(sanitized);
if (basename.startsWith('.')) {
  return res.status(403).json({ error: 'Hidden files not accessible' });
}
const filePath = path.join(downloadsDir, sanitized);`,
      correct: false,
      explanation: 'Hidden file filtering only blocks dot files but allows access to regular backup files with extensions like .bak, .backup, .old, or .tmp that often contain sensitive system and user data.'
    },
    {
      code: `await logFileAccess(req.user.id, sanitized);
const filePath = path.join(downloadsDir, sanitized);`,
      correct: false,
      explanation: 'Access logging does not prevent unauthorized file downloads. While audit trails are valuable, this does not stop attackers from accessing backup files containing sensitive information.'
    },
    {
      code: `if (sanitized.match(/[0-9]{4}-[0-9]{2}-[0-9]{2}/)) {
  return res.status(403).json({ error: 'Dated files not accessible' });
}
const filePath = path.join(downloadsDir, sanitized);`,
      correct: false,
      explanation: 'Date pattern filtering misses many backup file naming conventions. Backup files like "config.bak", "users.old", "database.backup", or "system~" do not contain date patterns but can expose sensitive data.'
    },
    {
      code: `const randomCheck = Math.random();
if (randomCheck < 0.1) {
  return res.status(403).json({ error: 'Random security check failed' });
}
const filePath = path.join(downloadsDir, sanitized);`,
      correct: false,
      explanation: 'Random access control provides no real security. Attackers can retry requests until successful and gain access to backup files containing sensitive credentials, user data, and system configurations.'
    }
  ]
}
