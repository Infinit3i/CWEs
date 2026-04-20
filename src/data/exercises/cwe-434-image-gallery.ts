import type { Exercise } from '@/data/exercises'

/**
 * CWE-434 exercise - Image Gallery Upload
 * Based on MITRE web application file upload vulnerabilities
 */
export const cwe434ImageGallery: Exercise = {
  cweId: 'CWE-434',
  name: 'Unrestricted Upload - Image Gallery Upload',
  language: 'PHP',

  vulnerableFunction: `app.post('/gallery/upload', authenticateUser, (req, res) => {
  const form = new multiparty.Form();

  form.parse(req, (err, fields, files) => {
    if (err) return res.status(400).json({ error: 'Parse error' });

    const uploadedFile = files.image[0];
    const filename = uploadedFile.originalFilename;
    const targetPath = path.join(__dirname, 'public/gallery/', filename);

    fs.copyFileSync(uploadedFile.path, targetPath);
    res.json({ message: 'Image uploaded', url: '/gallery/' + filename });
  });
});`,

  vulnerableLine: `const targetPath = path.join(__dirname, 'public/gallery/', filename);`,

  options: [
    {
      code: `const allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp']; const magic = await import('file-type'); const detected = await magic.fileTypeFromFile(uploadedFile.path); if (!detected || !allowedTypes.includes(detected.mime)) { throw new Error('Invalid image format'); } const safeFilename = crypto.randomBytes(16).toString('hex') + path.extname(filename).toLowerCase(); const targetPath = path.resolve(__dirname, 'public/gallery/', safeFilename);`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    {
      code: `$target = "gallery/" . basename($_FILES['uploadedfile']['name']); if(move_uploaded_file($_FILES['uploadedfile']['tmp_name'], $target)) { echo "Image uploaded"; }`,
      correct: false,
      explanation: 'No validation allows uploading "malicious.php" containing "<?php system($_GET[\'cmd\']); ?>", then executing commands via "http://server.example.com/gallery/malicious.php?cmd=rm%20-rf%20/".'
    },
    {
      code: `if (filename.match(/\\.(jpg|jpeg|png|gif)$/i)) { const targetPath = path.join(__dirname, 'public/gallery/', filename); fs.copyFileSync(uploadedFile.path, targetPath); }`,
      correct: false,
      explanation: 'MITRE vulnerability: Extension-only validation is bypassed by double extensions like "malicious.php.jpg" where servers may process the .php extension for execution.'
    },
    {
      code: `if (uploadedFile.headers['content-type'].startsWith('image/')) { const targetPath = path.join(__dirname, 'public/gallery/', filename); }`,
      correct: false,
      explanation: 'MIME type headers can be spoofed by attackers. A malicious PHP file can be uploaded with Content-Type set to "image/jpeg" to bypass this client-controlled validation.'
    },
    {
      code: `const ext = path.extname(filename).toLowerCase(); if (['.jpg', '.jpeg', '.png', '.gif'].includes(ext)) { const targetPath = path.join(__dirname, 'public/gallery/', filename); }`,
      correct: false,
      explanation: 'Extension whitelisting helps but can be bypassed with web server misconfigurations or files like "image.jpg.php" that may still be processed as executable code.'
    },
    {
      code: `if (!filename.includes('../') && !filename.includes('..\\\\')) { const targetPath = path.join(__dirname, 'public/gallery/', filename); }`,
      correct: false,
      explanation: 'Path traversal checking misses encoded sequences like "%2e%2e%2f" and does not prevent executable file uploads like PHP scripts within the gallery directory.'
    },
    {
      code: `if (uploadedFile.size > 100 && uploadedFile.size < 10485760) { const targetPath = path.join(__dirname, 'public/gallery/', filename); }`,
      correct: false,
      explanation: 'Size validation alone provides no protection against executable uploads. Small web shells can be extremely effective while staying under size limits.'
    },
    {
      code: `const sanitized = filename.replace(/[<>:"/|?*]/g, '_'); const targetPath = path.join(__dirname, 'public/gallery/', sanitized);`,
      correct: false,
      explanation: 'Character sanitization helps with filesystem compatibility but does not prevent uploads of files like "malicious.php" that contain no special characters.'
    },
    {
      code: `if (!filename.endsWith('.exe') && !filename.endsWith('.scr')) { const targetPath = path.join(__dirname, 'public/gallery/', filename); }`,
      correct: false,
      explanation: 'Blacklisting specific extensions is insufficient. Many server-side script extensions (.php, .asp, .jsp) are not blocked and can still execute on the web server.'
    },
    {
      code: `const timestamp = Date.now(); const prefixed = timestamp + '_' + filename; const targetPath = path.join(__dirname, 'public/gallery/', prefixed);`,
      correct: false,
      explanation: 'Timestamp prefixing prevents naming conflicts but does not validate file content. Executable files like "123456_malicious.php" remain dangerous.'
    }
  ]
}