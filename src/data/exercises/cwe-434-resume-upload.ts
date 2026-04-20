import type { Exercise } from '@/data/exercises'

/**
 * CWE-434 exercise - Resume Upload
 * Based on MITRE patterns for web application file upload vulnerabilities
 */
export const cwe434ResumeUpload: Exercise = {
  cweId: 'CWE-434',
  name: 'Unrestricted Upload - Resume Upload',

  vulnerableFunction: `app.post('/careers/upload-resume', (req, res) => {
  const upload = multer({ dest: './public/resumes/' });

  upload.single('resume')(req, res, (err) => {
    if (err) return res.status(400).json({ error: 'Upload failed' });

    const originalName = req.file.originalname;
    const finalPath = './public/resumes/' + originalName;

    fs.renameSync(req.file.path, finalPath);
    res.json({ message: 'Resume uploaded successfully' });
  });
});`,

  vulnerableLine: `const finalPath = './public/resumes/' + originalName;`,

  options: [
    {
      code: `const allowedMimes = ['application/pdf', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document']; const allowedExts = ['.pdf', '.doc', '.docx']; if (!allowedMimes.includes(req.file.mimetype)) { throw new Error('Invalid file type'); } const ext = path.extname(originalName).toLowerCase(); if (!allowedExts.includes(ext)) { throw new Error('Invalid extension'); } const safeFilename = 'resume_' + Date.now() + ext; const finalPath = path.resolve('./public/resumes/', safeFilename);`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    {
      code: `$target = "resumes/" . basename($_FILES['uploadedfile']['name']); if(move_uploaded_file($_FILES['uploadedfile']['tmp_name'], $target)) { echo "Resume uploaded"; }`,
      correct: false,
      explanation: 'No file type validation allows uploading executable files like "malicious.php" containing "<?php system($_GET[\'cmd\']); ?>", enabling remote code execution via direct file access.'
    },
    {
      code: `if (originalName.endsWith('.pdf') || originalName.endsWith('.doc') || originalName.endsWith('.docx')) { const finalPath = './public/resumes/' + originalName; }`,
      correct: false,
      explanation: 'Simple extension checking is bypassed by double extensions like "malicious.php.pdf" where servers may process the .php extension despite the .pdf suffix.'
    },
    {
      code: `if (req.file.mimetype.includes('application/')) { const finalPath = './public/resumes/' + originalName; fs.renameSync(req.file.path, finalPath); }`,
      correct: false,
      explanation: 'Broad MIME type checking allows many executable types like "application/x-httpd-php" which can still be processed as server-side scripts by the web server.'
    },
    {
      code: `if (!originalName.includes('.exe') && !originalName.includes('.bat')) { const finalPath = './public/resumes/' + originalName; fs.renameSync(req.file.path, finalPath); }`,
      correct: false,
      explanation: 'Blacklisting specific extensions is easily bypassed. Many server-side executable extensions exist (.php, .asp, .jsp, .pl) that are not blocked by this limited check.'
    },
    {
      code: `if (req.file.size < 5242880) { const finalPath = './public/resumes/' + originalName; fs.renameSync(req.file.path, finalPath); }`,
      correct: false,
      explanation: 'File size validation is important but does not prevent executable uploads. Small web shells can be very effective while staying under reasonable size limits.'
    },
    {
      code: `const sanitized = originalName.replace(/[^a-zA-Z0-9._-]/g, ''); const finalPath = './public/resumes/' + sanitized;`,
      correct: false,
      explanation: 'Character sanitization helps but still allows dangerous files like "malicious.php" if they contain only alphanumeric characters and allowed symbols.'
    },
    {
      code: `if (originalName && originalName.trim().length > 0) { const finalPath = './public/resumes/' + originalName.trim(); }`,
      correct: false,
      explanation: 'Basic existence and whitespace checking provides no security against malicious uploads. Any non-empty filename passes this minimal validation.'
    },
    {
      code: `const timestamp = new Date().toISOString(); const finalPath = './public/resumes/' + timestamp + '_' + originalName;`,
      correct: false,
      explanation: 'Adding timestamps helps prevent filename conflicts but does not validate file types. Executable files like "malicious.php" remain dangerous regardless of prefix.'
    },
    {
      code: `const lowercase = originalName.toLowerCase(); const finalPath = './public/resumes/' + lowercase; fs.renameSync(req.file.path, finalPath);`,
      correct: false,
      explanation: 'Case normalization alone provides no security against executable uploads. "malicious.php" in lowercase is still a dangerous server-side script.'
    }
  ]
}