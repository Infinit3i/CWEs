import type { Exercise } from '@/data/exercises'

/**
 * CWE-862 exercise - File Sharing System
 * Based on MITRE unauthorized file access patterns
 */
export const cwe862FileSharing: Exercise = {
  cweId: 'CWE-862',
  name: 'Missing Authorization - File Sharing System',

  vulnerableFunction: `app.get('/api/files/:fileId/download', authenticateUser, (req, res) => {
  const fileId = req.params.fileId;

  // Get file metadata
  const query = 'SELECT filename, filepath, mimetype, size FROM shared_files WHERE id = ?';
  db.query(query, [fileId], (err, results) => {
    if (err || results.length === 0) {
      return res.status(404).json({ error: 'File not found' });
    }

    const file = results[0];
    res.download(file.filepath, file.filename);
  });
});`,

  vulnerableLine: `const query = 'SELECT filename, filepath, mimetype, size FROM shared_files WHERE id = ?';`,

  options: [
    {
      code: `const query = 'SELECT f.filename, f.filepath, f.mimetype FROM shared_files f LEFT JOIN file_permissions p ON f.id = p.file_id WHERE f.id = ? AND (f.owner_id = ? OR p.user_id = ? OR f.is_public = 1)'; db.query(query, [fileId, req.user.id, req.user.id], (err, results) => {`,
      correct: true,
      explanation: `Check user permissions before access`
    },
    {
      code: `if (!session_is_registered("username")) { echo "invalid session detected!"; exit; } download_file($fileId);`,
      correct: false,
      explanation: 'Authentication-only validation allows any authenticated user to download any file by providing arbitrary file identifiers, exposing private documents and sensitive data.'
    },
    {
      code: `if (req.user && req.user.id) { // User authenticated, allow download of any file const query = \'SELECT * FROM shared_files WHERE id = ?\'; }`,
      correct: false,
      explanation: 'MITRE vulnerability: Basic authentication without access control allows any logged-in user to access any file by manipulating the fileId parameter.'
    },
    {
      code: `if (req.headers.authorization && req.headers.authorization.includes(\'Bearer\')) { // Valid token, allow file access }`,
      correct: false,
      explanation: 'Token validation confirms authentication but provides no authorization logic to determine if the user has permission to access the specific file being requested.'
    },
    {
      code: `if (parseInt(fileId) > 0) { // Valid file ID format, allow download const query = \'SELECT * FROM shared_files WHERE id = ?\'; }`,
      correct: false,
      explanation: 'Input validation ensures proper ID format but implements no access control. Any valid file ID can be downloaded regardless of ownership or sharing permissions.'
    },
    {
      code: `if (req.user.storageQuota > req.user.storageUsed) { // User has storage space, allow any file download }`,
      correct: false,
      explanation: 'Storage quota checking relates to upload capacity but has no bearing on download authorization. Available storage should not grant access to other users\' private files.'
    },
    {
      code: `if (req.user.accountType === \'premium\') { // Premium user, allow access to any file }`,
      correct: false,
      explanation: 'Account type checking may determine feature access but should not override file ownership and sharing permissions. Premium users should still only access authorized files.'
    },
    {
      code: `if (req.ip && req.ip === req.user.lastLoginIP) { // IP matches last login, allow file download }`,
      correct: false,
      explanation: 'IP validation may help detect session anomalies but does not provide authorization controls for file access. Legitimate IPs should still respect sharing permissions.'
    },
    {
      code: `if (Date.now() - req.user.lastActivity < 1800000) { // Recently active, allow access to any file }`,
      correct: false,
      explanation: 'Activity-based validation helps with session security but does not implement authorization logic to ensure users only access files they own or have permission to view.'
    },
    {
      code: `if (req.user.emailDomain === \'company.com\') { // Company email, allow access to any shared file }`,
      correct: false,
      explanation: 'Email domain checking may indicate organizational membership but should not grant universal file access. Proper sharing permissions should still be enforced within organizations.'
    }
  ]
}