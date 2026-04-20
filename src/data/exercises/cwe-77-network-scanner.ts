import type { Exercise } from '@/data/exercises'

/**
 * CWE-77 exercise: Network scanning command injection
 * Based on network diagnostic tools that execute system commands
 */
export const cwe77NetworkScanner: Exercise = {
  cweId: 'CWE-77',
  name: 'Command Injection - Network Diagnostic Scanner',

  vulnerableFunction: `function scanNetworkHost(hostAddress, scanType, options) {
  const { exec } = require('child_process');

  // Validate scan type
  const validScanTypes = ['ping', 'traceroute', 'portscan'];
  if (!validScanTypes.includes(scanType)) {
    throw new Error('Invalid scan type');
  }

  let cmd;

  switch (scanType) {
    case 'ping':
      const count = options.count || 4;
      cmd = \`ping -c \${count} \${hostAddress}\`;
      break;
    case 'traceroute':
      cmd = \`traceroute \${hostAddress}\`;
      break;
    case 'portscan':
      const portRange = options.ports || '80,443,22';
      cmd = \`nmap -p \${portRange} \${hostAddress}\`;
      break;
  }

  return new Promise((resolve, reject) => {
    exec(cmd, { timeout: 30000 }, (error, stdout, stderr) => {
      if (error) {
        reject(\`Scan failed: \${error.message}\`);
        return;
      }

      resolve({
        success: true,
        target: hostAddress,
        scanType: scanType,
        output: stdout,
        command: cmd
      });
    });
  });
}`,

  vulnerableLine: `cmd = \`ping -c \${count} \${hostAddress}\`;`,

  options: [
    {
      code: `function scanNetworkHost(hostAddress, scanType, options) {
  const { spawn } = require('child_process');
  const net = require('net');

  // Validate scan type
  const validScanTypes = ['ping', 'traceroute'];
  if (!validScanTypes.includes(scanType)) {
    throw new Error('Invalid scan type');
  }

  // Validate IP address format
  if (!net.isIP(hostAddress)) {
    throw new Error('Invalid IP address');
  }

  // Validate count parameter
  const count = parseInt(options.count) || 4;
  if (count < 1 || count > 10) {
    throw new Error('Invalid ping count');
  }

  return new Promise((resolve, reject) => {
    let command, args;

    if (scanType === 'ping') {
      command = 'ping';
      args = ['-c', count.toString(), hostAddress];
    } else {
      command = 'traceroute';
      args = [hostAddress];
    }

    const proc = spawn(command, args);
    let output = '';

    proc.stdout.on('data', (data) => {
      output += data;
    });

    proc.on('close', (code) => {
      resolve({ success: true, output: output });
    });
  });
}`,
      correct: true,
      explanation: `Correct! Using spawn() with validated arguments prevents command injection. IP address validation, parameter sanitization, and argument array usage ensure safe command execution.`
    },
    // Network scanning command injection vulnerabilities
    {
      code: `cmd = \`ping -c \${count} \${hostAddress}\`;
exec(cmd);`,
      correct: false,
      explanation: 'Unvalidated parameters in ping command. A count like "1; cat /etc/passwd" or hostAddress with injection would execute arbitrary commands alongside ping.'
    },
    {
      code: `cmd = \`nmap -p \${portRange} \${hostAddress}\`;
exec(cmd);`,
      correct: false,
      explanation: 'Nmap command with unsanitized input enables injection. Port ranges like "80; rm -rf /" or hostnames with shell metacharacters can execute destructive commands.'
    },
    {
      code: `cmd = \`traceroute \${hostAddress}\`;
exec(cmd);`,
      correct: false,
      explanation: 'Traceroute with unvalidated host input allows injection. Hostnames containing command separators or shell metacharacters can execute arbitrary commands.'
    },
    {
      code: `const timeout = options.timeout || 30;
cmd = \`timeout \${timeout} ping \${hostAddress}\`;
exec(cmd);`,
      correct: false,
      explanation: 'Multiple unvalidated parameters create multiple injection points. Both timeout values and hostnames can contain malicious command sequences.'
    },
    {
      code: `if (hostAddress.includes(' ')) {
    throw new Error('Invalid hostname');
}
cmd = \`ping \${hostAddress}\`;
exec(cmd);`,
      correct: false,
      explanation: 'Space filtering is insufficient protection. Other shell metacharacters like semicolons, pipes, backticks, and command substitution remain exploitable.'
    },
    {
      code: `const safeHost = hostAddress.replace(/[;&|]/g, '');
cmd = \`ping \${safeHost}\`;
exec(cmd);`,
      correct: false,
      explanation: 'Character filtering misses other injection vectors. Backticks, $(), newlines, and other shell metacharacters can still be used for command injection.'
    },
    {
      code: `const cmd = ['ping', '-c', count, hostAddress].join(' ');
exec(cmd);`,
      correct: false,
      explanation: 'Array joining does not sanitize individual elements. Malicious content in array elements still creates injection vulnerabilities when joined into a shell command.'
    },
    {
      code: `if (net.isIP(hostAddress)) {
    cmd = \`ping \${hostAddress} && echo "Ping completed"\`;
    exec(cmd);
}`,
      correct: false,
      explanation: 'IP validation helps but command chaining introduces new risks. The echo command and && operator create additional complexity that could be exploited.'
    },
    {
      code: `const escapedHost = require('shell-escape')([hostAddress]);
cmd = \`ping \${escapedHost}\`;
exec(cmd);`,
      correct: false,
      explanation: 'Shell escaping libraries may have edge cases or bypasses. Using spawn() with argument arrays is more reliable than depending on escaping functions.'
    },
    {
      code: `const cmd = util.format('netstat -an | grep %s', hostAddress);
exec(cmd);`,
      correct: false,
      explanation: 'Complex command pipelines with string formatting create injection opportunities. The grep pattern can contain metacharacters that alter pipeline execution.'
    }
  ]
}