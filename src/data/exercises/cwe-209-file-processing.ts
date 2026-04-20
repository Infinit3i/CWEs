import type { Exercise } from '@/data/exercises'

/**
 * CWE-209: Information Exposure Through File Processing Errors
 * Scenario: File upload service exposing system paths and configuration
 * Based on MITRE demonstrative examples showing file system error leakage
 */
export const cwe209FileProcessing: Exercise = {
  cweId: 'CWE-209',
  name: 'Information Exposure - File Processing Errors',

  vulnerableFunction: `app.post('/api/upload', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file provided' });
    }
    
    const uploadedFile = req.file;
    const originalName = uploadedFile.originalname;
    const tempPath = uploadedFile.path;
    
    // Define target directory structure
    const uploadDate = new Date().toISOString().split('T')[0];
    const targetDir = path.join('/var/uploads', req.user.department, uploadDate);
    const targetPath = path.join(targetDir, \`\${Date.now()}_\${originalName}\`);
    
    console.log('Processing upload:', {
      originalName,
      tempPath,
      targetPath,
      userDept: req.user.department
    });
    
    // Create directory if it doesn't exist
    await fs.mkdir(targetDir, { recursive: true });
    
    // Move file from temp location to target
    await fs.rename(tempPath, targetPath);
    
    // Process file based on type
    let processedData;
    const fileExt = path.extname(originalName).toLowerCase();
    
    switch (fileExt) {
      case '.csv':
        processedData = await processCsvFile(targetPath);
        break;
      case '.json':
        processedData = await processJsonFile(targetPath);
        break;
      case '.xml':
        processedData = await processXmlFile(targetPath);
        break;
      default:
        processedData = await processGenericFile(targetPath);
    }
    
    res.json({
      message: 'File uploaded and processed successfully',
      fileId: path.basename(targetPath),
      processedData: processedData
    });
    
  } catch (error) {
    console.error('File processing error:', error);
    
    res.status(500).json({
      error: 'File processing failed',
      details: {
        message: error.message,
        code: error.code,
        errno: error.errno,
        syscall: error.syscall,
        path: error.path,
        dest: error.dest,
        stack: error.stack
      },
      fileInfo: {
        originalName: req.file?.originalname,
        tempPath: req.file?.path,
        targetPath: targetPath,
        targetDirectory: targetDir,
        uploadDirectory: '/var/uploads',
        configPath: '/etc/app/upload-config.json',
        logPath: '/var/log/uploads.log'
      },
      systemContext: {
        workingDir: process.cwd(),
        homeDir: process.env.HOME,
        user: process.env.USER,
        hostname: require('os').hostname(),
        platform: process.platform,
        nodeVersion: process.version,
        permissions: {
          uid: process.getuid(),
          gid: process.getgid(),
          groups: process.getgroups()
        }
      },
      troubleshooting: [
        'Check file permissions on /var/uploads',
        'Verify disk space: df -h /var/uploads',
        'Check upload config: cat /etc/app/upload-config.json',
        'Review logs: tail -f /var/log/uploads.log'
      ]
    });
  }
});`,

  vulnerableLine: `res.status(500).json({`,

  options: [
    {
      code: `// Log detailed error securely and return safe error message
const errorId = crypto.randomUUID();

// Comprehensive error logging for debugging
console.error('File upload error:', {
  errorId,
  userId: req.user?.id,
  originalFilename: req.file?.originalname,
  error: error.message,
  code: error.code,
  path: error.path,
  stack: error.stack,
  timestamp: new Date().toISOString(),
  userAgent: req.get('User-Agent'),
  ip: req.ip
});

// Clean up temporary file if it exists
if (req.file?.path) {
  try {
    await fs.unlink(req.file.path);
  } catch (unlinkError) {
    console.error('Temp file cleanup failed:', unlinkError);
  }
}

res.status(500).json({
  error: 'Upload failed',
  errorId: errorId,
  message: 'Please try again or contact support if the problem persists'
});`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    // Real MITRE demonstrative examples as wrong answers
    {
      code: `res.status(500).json({
  error: 'File processing failed',
  details: {
    message: error.message,
    path: error.path,
    syscall: error.syscall,
    stack: error.stack
  },
  fileInfo: {
    targetPath: targetPath,
    uploadDirectory: '/var/uploads',
    configPath: '/etc/app/upload-config.json'
  },
  systemContext: {
    workingDir: process.cwd(),
    user: process.env.USER,
    permissions: process.getuid()
  }
});`,
      correct: false,
      explanation: 'Direct from MITRE CWE-209: Exposing detailed file system errors reveals critical system information including directory structures, configuration file paths, process permissions, and system user context. Attackers can use this information to plan privilege escalation and targeted file system attacks.'
    },
    {
      code: `res.status(500).json({
  error: 'Upload failed',
  fileError: error.message,
  failedPath: error.path,
  suggestion: 'Check file permissions on /var/uploads'
});`,
      correct: false,
      explanation: 'File system error messages from MITRE examples expose directory paths and system configuration details. The troubleshooting suggestions provide attackers with specific commands and file paths to gather more system information.'
    },
    {
      code: `const pathInfo = error.path ? path.dirname(error.path) : 'unknown';
res.status(500).json({
  error: 'File operation failed',
  location: pathInfo,
  operation: error.syscall,
  code: error.code
});`,
      correct: false,
      explanation: 'Exposing directory paths and system call information reveals file system structure and operation details that can help attackers understand system architecture and identify potential attack vectors.'
    },
    {
      code: `res.status(500).json({
  error: 'Processing error',
  type: 'FileSystemError',
  errno: error.errno,
  syscall: error.syscall,
  timestamp: Date.now()
});`,
      correct: false,
      explanation: 'System call details and error numbers provide specific information about system capabilities and failure modes that can be valuable for attackers planning system-level exploits.'
    },
    {
      code: `if (error.code === 'EACCES') {
  res.status(500).json({
    error: 'Permission denied',
    path: error.path,
    suggestion: 'Check directory permissions'
  });
} else {
  res.status(500).json({ error: 'File operation failed' });
}`,
      correct: false,
      explanation: 'Permission error details reveal specific file paths and access control information. This helps attackers identify restricted directories and understand the system\'s permission structure for potential privilege escalation.'
    },
    {
      code: `const sanitizedPath = error.path?.replace(/\\/home\\/[^/]+/g, '/home/[user]');
res.status(500).json({
  error: 'File error',
  location: sanitizedPath,
  details: error.message
});`,
      correct: false,
      explanation: 'Partial path sanitization still exposes valuable directory structure information. Even with user directory masking, other sensitive paths and error details can reveal system architecture and configuration.'
    },
    {
      code: `res.status(500).json({
  error: 'Upload unsuccessful',
  debug: {
    stage: 'file_processing',
    fileType: path.extname(req.file?.originalname),
    errorCode: error.code
  }
});`,
      correct: false,
      explanation: 'Processing stage information and error codes can reveal application workflow and system capabilities, providing attackers with insights into potential attack points and system behavior.'
    },
    {
      code: `const errorLog = \`\${Date.now()}: \${error.message} at \${error.path}\`;
fs.appendFileSync('/var/log/app-errors.log', errorLog);
res.status(500).json({ error: 'Upload failed' });`,
      correct: false,
      explanation: 'While the response is generic, synchronous file logging can cause performance issues and may expose log file paths. Additionally, if there are log injection vulnerabilities, this could be exploited.'
    },
    {
      code: `if (req.file) {
  await fs.unlink(req.file.path).catch(console.error);
}
res.status(500).json({
  error: 'Processing failed',
  hint: error.message.substring(0, 30)
});`,
      correct: false,
      explanation: 'Partial error message exposure can still reveal sensitive information about file paths, system calls, or configuration details, especially when combined with other information gathering techniques.'
    }
  ]
}
