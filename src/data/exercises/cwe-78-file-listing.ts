import type { Exercise } from '@/data/exercises'

export const cwe78FileListing: Exercise = {
  cweId: 'CWE-78',
  name: 'OS Command Injection - Directory Listing',
  language: 'Python',

  vulnerableFunction: `import subprocess
import os

def list_user_files(user_name):
    # List files in user's home directory
    command = f"ls -l /home/{user_name}"

    try:
        result = subprocess.run(command, shell=True,
                               capture_output=True, text=True)
        if result.returncode == 0:
            return result.stdout
        else:
            raise Exception(f"Command failed: {result.stderr}")
    except Exception as e:
        raise e`,

  vulnerableLine: `command = f"ls -l /home/{user_name}"`,

  options: [
    {
      code: `import re

def list_user_files(user_name):
    # Sanitize username to alphanumeric and safe chars
    safe_user = re.sub(r'[^a-zA-Z0-9_-]', '', user_name)

    # Use list arguments with subprocess to avoid shell injection
    try:
        result = subprocess.run(['ls', '-l', f'/home/{safe_user}'],
                               capture_output=True, text=True, shell=False)
        if result.returncode == 0:
            return result.stdout
        else:
            raise Exception(f"Command failed: {result.stderr}")
    except Exception as e:
        raise e`,
      correct: true,
      explanation: `Use subprocess with list arguments and shell=False to prevent command injection`
    },
    {
      code: `command = f"ls -l /home/{user_name}"`,
      correct: false,
      explanation: 'Direct string interpolation with shell=True allows command injection through special characters like semicolons, pipes, and command substitution'
    },
    {
      code: `command = f"ls -l /home/{user_name.replace(';', '')}"`,
      correct: false,
      explanation: 'Removing only semicolons misses other dangerous shell metacharacters like &&, ||, |, `, $(, backticks, and redirect operators'
    },
    {
      code: `import urllib.parse
command = f"ls -l /home/{urllib.parse.quote(user_name)}"`,
      correct: false,
      explanation: 'URL encoding does not prevent command injection in shell context. The shell interprets encoded characters, and attackers can use non-encoded shell metacharacters'
    },
    {
      code: `import json
command = f"ls -l /home/{json.dumps(user_name)}"`,
      correct: false,
      explanation: 'JSON encoding adds quotes but does not prevent shell injection. Payloads like user"; rm -rf /" can escape quotes and execute arbitrary commands'
    },
    {
      code: `command = f"ls -l /home/{user_name[:20]}"`,
      correct: false,
      explanation: 'Length truncation does not prevent command injection. Short payloads like ";rm *", "&&id", or "|cat /etc/passwd" are effective within character limits'
    },
    {
      code: `command = f"ls -l /home/{user_name.lower()}"`,
      correct: false,
      explanation: 'Case conversion does not prevent command injection. Lowercase shell commands and metacharacters like ";", "&&", "||", "|" remain functional'
    },
    {
      code: `command = f"ls -l /home/{user_name.replace('<', '').replace('>', '')}"`,
      correct: false,
      explanation: 'Removing only redirect operators is insufficient. Command injection uses semicolons, pipes, command substitution ($()), backticks, and other dangerous metacharacters'
    },
    {
      code: `command = f"ls -l /home/{user_name.strip()}"`,
      correct: false,
      explanation: 'Trimming whitespace does not address command injection. Malicious commands can be crafted without leading/trailing spaces while containing dangerous metacharacters'
    },
    {
      code: `if '..' in user_name:
    raise ValueError('Invalid path')
command = f"ls -l /home/{user_name}"`,
      correct: false,
      explanation: 'Checking for path traversal only addresses one threat. Command injection through shell metacharacters like ;, &&, |, $(, backticks remains possible'
    },
    {
      code: `command = f"ls -l '/home/{user_name}'"`,
      correct: false,
      explanation: 'Single quotes around the path do not prevent injection. Attackers can close the quotes with a single quote and append malicious commands: user\'; rm -rf /; #'
    }
  ]
}