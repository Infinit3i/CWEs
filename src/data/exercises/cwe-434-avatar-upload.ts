import type { Exercise } from '@/data/exercises'

/**
 * CWE-434 exercise - Avatar Upload
 * Based on MITRE demonstrative examples for unrestricted file upload vulnerabilities
 */
export const cwe434AvatarUpload: Exercise = {
  cweId: 'CWE-434',
  name: 'Unrestricted Upload - Avatar Upload',

  vulnerableFunction: `app.post('/upload/avatar', upload.single('avatar'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }

  const filename = req.file.originalname;
  const uploadPath = path.join(__dirname, 'public/avatars/', filename);

  fs.writeFileSync(uploadPath, req.file.buffer);
  res.json({ message: 'Avatar uploaded', url: '/avatars/' + filename });
});`,

  vulnerableLine: `const uploadPath = path.join(__dirname, 'public/avatars/', filename);`,

  options: [
    {
      code: `const allowedTypes = ['image/jpeg', 'image/png', 'image/gif']; const allowedExts = ['.jpg', '.jpeg', '.png', '.gif']; if (!allowedTypes.includes(req.file.mimetype) || !allowedExts.includes(path.extname(filename).toLowerCase())) { return res.status(400).json({ error: 'Invalid file type' }); } const safeFilename = crypto.randomUUID() + path.extname(filename).toLowerCase();`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    {
      code: `const target = "pictures/" + basename($_FILES['uploadedfile']['name']); if(move_uploaded_file($_FILES['uploadedfile']['tmp_name'], $target)) { echo "Upload successful"; }`,
      correct: false,
      explanation: 'No validation allows uploading "malicious.php" containing "<?php system($_GET[\'cmd\']); ?>", then executing arbitrary commands via "http://server.example.com/pictures/malicious.php?cmd=ls%20-l".'
    },
    {
      code: `if (req.file.mimetype.startsWith('image/')) { const uploadPath = path.join(__dirname, 'public/avatars/', filename); fs.writeFileSync(uploadPath, req.file.buffer); }`,
      correct: false,
      explanation: 'MIME type alone is insufficient. Attackers can craft files with image MIME types but executable extensions like "shell.php.gif" or use double extensions to bypass basic validation.'
    },
    {
      code: `const ext = path.extname(filename); if (['.jpg', '.png', '.gif'].includes(ext)) { const uploadPath = path.join(__dirname, 'public/avatars/', filename); }`,
      correct: false,
      explanation: 'Extension checking alone misses attacks like "malicious.php.jpg" where servers may process the .php extension despite the .jpg suffix, especially with certain server configurations.'
    },
    {
      code: `if (req.file.size < 5000000) { const uploadPath = path.join(__dirname, 'public/avatars/', filename); fs.writeFileSync(uploadPath, req.file.buffer); }`,
      correct: false,
      explanation: 'File size validation is important but does not prevent execution of uploaded scripts. Small PHP shells can be very effective while staying under size limits.'
    },
    {
      code: `const sanitized = filename.replace(/[^a-zA-Z0-9.]/g, '_'); const uploadPath = path.join(__dirname, 'public/avatars/', sanitized);`,
      correct: false,
      explanation: 'Character sanitization helps but still allows dangerous files like "malicious.php" if the extension is preserved. Does not validate actual file content or type.'
    },
    {
      code: `if (filename.includes('.exe') || filename.includes('.bat')) { return res.status(400).json({ error: 'Executable files not allowed' }); }`,
      correct: false,
      explanation: 'Blacklisting specific extensions is easily bypassed. Many server-side executable extensions exist (.php, .asp, .jsp, .pl) that are not in this limited blacklist.'
    },
    {
      code: `const lowercase = filename.toLowerCase(); const uploadPath = path.join(__dirname, 'public/avatars/', lowercase);`,
      correct: false,
      explanation: 'Case normalization alone does not prevent execution. "malicious.php" converted to lowercase is still a dangerous PHP file that can execute server-side code.'
    },
    {
      code: `if (req.file.originalname && req.file.originalname.length > 0) { const uploadPath = path.join(__dirname, 'public/avatars/', req.file.originalname); }`,
      correct: false,
      explanation: 'Basic existence checking provides no security against malicious uploads. Any non-empty filename passes this validation, including dangerous executable files.'
    },
    {
      code: `const timestamp = Date.now(); const uploadPath = path.join(__dirname, 'public/avatars/', timestamp + '_' + filename);`,
      correct: false,
      explanation: 'Adding timestamps helps prevent conflicts but does not change the file extension or content validation. "malicious.php" remains executable regardless of prefix.'
    }
  ]
}