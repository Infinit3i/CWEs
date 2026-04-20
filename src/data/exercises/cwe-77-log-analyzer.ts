import type { Exercise } from '@/data/exercises'

/**
 * CWE-77 exercise: Log file analysis command injection
 * Based on log processing systems that execute OS commands
 */
export const cwe77LogAnalyzer: Exercise = {
  cweId: 'CWE-77',
  name: 'Command Injection - Log File Analysis System',
  language: 'Go',

  vulnerableFunction: `function analyzeLogFile(logPath, searchPattern, outputFormat) {
  const { exec } = require('child_process');

  // Validate output format
  const validFormats = ['text', 'json', 'csv'];
  if (!validFormats.includes(outputFormat)) {
    throw new Error('Invalid output format');
  }

  // Build grep command for log analysis
  let cmd = \`grep "\${searchPattern}" \${logPath}\`;

  // Add formatting based on output type
  if (outputFormat === 'json') {
    cmd += ' | jq -R -s -c "split(\\"\\n\\")[:-1]"';
  } else if (outputFormat === 'csv') {
    cmd += \` | sed 's/,/\\\\,/g' | sed 's/^/"\${logPath}",/' | sed 's/$/"/'\`;
  }

  // Add line count
  cmd += ' | wc -l';

  return new Promise((resolve, reject) => {
    exec(cmd, { timeout: 30000 }, (error, stdout, stderr) => {
      if (error) {
        reject(\`Analysis failed: \${error.message}\`);
        return;
      }

      resolve({
        success: true,
        matches: parseInt(stdout.trim()),
        command: cmd
      });
    });
  });
}`,

  vulnerableLine: `let cmd = \`grep "\${searchPattern}" \${logPath}\`;`,

  options: [
    {
      code: `function analyzeLogFile(logPath, searchPattern, outputFormat) {
  const { spawn } = require('child_process');
  const path = require('path');

  // Validate inputs
  const validFormats = ['text', 'json', 'csv'];
  if (!validFormats.includes(outputFormat)) {
    throw new Error('Invalid output format');
  }

  // Sanitize file path
  const sanitizedPath = path.resolve(logPath);
  if (!sanitizedPath.startsWith('/var/log/')) {
    throw new Error('Invalid log path');
  }

  // Use spawn with individual arguments
  return new Promise((resolve, reject) => {
    const grep = spawn('grep', ['-c', searchPattern, sanitizedPath]);
    let output = '';

    grep.stdout.on('data', (data) => {
      output += data;
    });

    grep.on('close', (code) => {
      resolve({ success: true, matches: parseInt(output.trim()) });
    });
  });
}`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    // Log analysis command injection vulnerabilities
    {
      code: `let cmd = \`grep "\${searchPattern}" \${logPath}\`;
exec(cmd);`,
      correct: false,
      explanation: 'Unescaped user input in grep command. A search pattern like "error"; cat /etc/passwd would execute as grep "error"; cat /etc/passwd, exposing sensitive files.'
    },
    {
      code: `cmd += ' | jq -R -s -c "split(\\"\\n\\")[:-1]"';
exec(cmd);`,
      correct: false,
      explanation: 'Complex command pipelines amplify injection risk. Multiple stages provide numerous injection points where malicious input can alter command execution.'
    },
    {
      code: `cmd += \` | sed 's/^/"\${logPath}",/' | sed 's/$/"/'\`;
exec(cmd);`,
      correct: false,
      explanation: 'Sed commands with user input enable injection. Log paths containing sed metacharacters or command separators can break out of the sed command structure.'
    },
    {
      code: `const cmd = \`awk '/\${searchPattern}/ {print NR, $0}' \${logPath}\`;
exec(cmd);`,
      correct: false,
      explanation: 'AWK pattern injection allows code execution. Malicious patterns can contain AWK functions or system() calls that execute arbitrary commands.'
    },
    {
      code: `if (!searchPattern.includes(';')) {
    const cmd = \`grep "\${searchPattern}" \${logPath}\`;
    exec(cmd);
}`,
      correct: false,
      explanation: 'Semicolon filtering is insufficient. Other injection vectors like backticks, $(), pipes, and AWK expressions can still execute commands.'
    },
    {
      code: `const escapedPattern = searchPattern.replace(/"/g, '\\\\"');
const cmd = \`grep "\${escapedPattern}" \${logPath}\`;
exec(cmd);`,
      correct: false,
      explanation: 'Quote escaping only addresses one injection vector. Command substitution, pipes, and other shell metacharacters remain exploitable.'
    },
    {
      code: `const cmd = \`find \${logPath} -type f -exec grep "\${searchPattern}" {} +\`;
exec(cmd);`,
      correct: false,
      explanation: 'Find with grep creates multiple injection points. Both the path and search pattern can contain malicious content that alters command execution.'
    },
    {
      code: `const cmd = util.format('tail -f %s | grep --line-buffered "%s"', logPath, searchPattern);
exec(cmd);`,
      correct: false,
      explanation: 'String formatting does not sanitize shell metacharacters. Both parameters can contain command injection payloads that execute during tail/grep processing.'
    },
    {
      code: `const encoded = Buffer.from(searchPattern).toString('hex');
const cmd = \`echo \${encoded} | xxd -r -p | grep -f - \${logPath}\`;
exec(cmd);`,
      correct: false,
      explanation: 'Hex encoding with complex pipelines still allows injection. The overall command structure can be manipulated through other parameters or encoding bypasses.'
    },
    {
      code: `if (searchPattern.match(/^[a-zA-Z0-9 ]+$/)) {
    const cmd = \`grep "\${searchPattern}" \${logPath} | head -\${maxLines}\`;
    exec(cmd);
}`,
      correct: false,
      explanation: 'Alphanumeric validation with additional parameters creates new injection points. The maxLines parameter is unvalidated and can inject commands.'
    }
  ]
}