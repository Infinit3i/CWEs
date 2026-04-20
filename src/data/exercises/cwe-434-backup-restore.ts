import type { Exercise } from '@/data/exercises'

/**
 * CWE-434 exercise - Backup File Restore
 * Based on MITRE Java servlet with multiple validation weaknesses
 */
export const cwe434BackupRestore: Exercise = {
  cweId: 'CWE-434',
  name: 'Unrestricted Upload - Backup File Restore',
  language: 'PHP',

  vulnerableFunction: `app.post('/admin/restore-backup', requireAdmin, (req, res) => {
  const upload = multer({ dest: '/tmp/uploads/' });

  upload.single('backup')(req, res, (err) => {
    if (err) return res.status(400).json({ error: 'Upload failed' });

    const backupFile = req.file.originalname;
    const restorePath = '/var/backups/restore/' + backupFile;

    fs.copyFileSync(req.file.path, restorePath);
    execSync(\`tar -xzf \${restorePath} -C /var/app/data/\`);
    res.json({ message: 'Backup restored successfully' });
  });
});`,

  vulnerableLine: `const restorePath = '/var/backups/restore/' + backupFile;`,

  options: [
    {
      code: `const allowedExts = ['.tar.gz', '.tgz', '.tar.bz2']; const ext = path.extname(backupFile).toLowerCase(); const doubleExt = backupFile.toLowerCase().match(/\\.(tar\\.gz|tgz|tar\\.bz2)$/); if (!doubleExt) { throw new Error('Invalid backup format'); } const safeFilename = crypto.randomUUID() + doubleExt[0]; const restorePath = path.resolve('/var/backups/restore/', safeFilename); if (!restorePath.startsWith('/var/backups/restore/')) { throw new Error('Path validation failed'); }`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    {
      code: `String filename = pLine.substring(pLine.lastIndexOf("\\\\"), pLine.lastIndexOf("\\")); BufferedWriter bw = new BufferedWriter(new FileWriter(uploadLocation+filename, true));`,
      correct: false,
      explanation: 'Extracts filename without validation, allowing path traversal ("../") to write files outside intended directory AND executable uploads (.asp, .jsp files) for remote code execution.'
    },
    {
      code: `if (backupFile.endsWith('.tar.gz') || backupFile.endsWith('.zip')) { const restorePath = '/var/backups/restore/' + backupFile; }`,
      correct: false,
      explanation: 'Simple extension checking misses double extensions like "malicious.php.tar.gz" and allows path traversal sequences in the filename portion before the extension.'
    },
    {
      code: `if (!backupFile.includes('../')) { const restorePath = '/var/backups/restore/' + backupFile; fs.copyFileSync(req.file.path, restorePath); }`,
      correct: false,
      explanation: 'Path traversal checking misses encoded sequences like "%2e%2e%2f", absolute paths, and does not validate file types. Also vulnerable to executable file uploads.'
    },
    {
      code: `if (req.file.mimetype === 'application/gzip' || req.file.mimetype === 'application/x-gzip') { const restorePath = '/var/backups/restore/' + backupFile; }`,
      correct: false,
      explanation: 'MIME type validation can be spoofed and does not prevent path traversal attacks through malicious filenames or validate that the content is actually a safe backup file.'
    },
    {
      code: `const sanitized = backupFile.replace(/[^a-zA-Z0-9._-]/g, ''); const restorePath = '/var/backups/restore/' + sanitized;`,
      correct: false,
      explanation: 'Character filtering removes some dangerous characters but still allows files like "malicious.tar.gz" containing executable content, and may break legitimate backup filenames.'
    },
    {
      code: `if (backupFile.match(/^backup_\\d{4}-\\d{2}-\\d{2}/)) { const restorePath = '/var/backups/restore/' + backupFile; }`,
      correct: false,
      explanation: 'Filename pattern validation helps but does not prevent path traversal if the pattern allows "../backup_2024-01-01.tar.gz" or validate actual file content and type.'
    },
    {
      code: `if (req.file.size > 1048576 && req.file.size < 1073741824) { const restorePath = '/var/backups/restore/' + backupFile; }`,
      correct: false,
      explanation: 'Size validation is good practice but provides no protection against malicious file types, path traversal, or executable content within size limits.'
    },
    {
      code: `const basename = path.basename(backupFile); const restorePath = '/var/backups/restore/' + basename;`,
      correct: false,
      explanation: 'While basename() removes directory components, it does not validate file types or extensions. Files like "malicious.php" are still dangerous even with path components stripped.'
    },
    {
      code: `if (!backupFile.toLowerCase().includes('admin') && !backupFile.includes('config')) { const restorePath = '/var/backups/restore/' + backupFile; }`,
      correct: false,
      explanation: 'Blacklisting specific terms is easily bypassed and does not address the core issues of file type validation or path traversal prevention in backup file uploads.'
    }
  ]
}