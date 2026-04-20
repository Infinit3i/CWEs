import type { Exercise } from '@/data/exercises'

/**
 * CWE-22 exercise - File Download Endpoint
 * Based on MITRE demonstrative examples for path traversal vulnerabilities
 */
export const cwe22FileDownload: Exercise = {
  cweId: 'CWE-22',
  name: 'Path Traversal - File Download Endpoint',
  language: 'Python',

  vulnerableFunction: `def read_file(filename):
    path = '/uploads/' + filename
    return open(path, 'r').read()`,

  vulnerableLine: `path = '/uploads/' + filename`,

  options: [
    {
      code: `safe_name = os.path.basename(filename)
path = '/uploads/' + safe_name`,
      correct: true,
      explanation: `os.path.basename() strips path components, prevents traversal`
    },
    {
      code: `cleaned = filename.replace('../', '')
path = '/uploads/' + cleaned`,
      correct: false,
      explanation: 'Only removes first "../" - multiple sequences still work'
    },
    {
      code: `if filename.startswith('/uploads/'):
    path = filename`,
      correct: false,
      explanation: 'Path like "/uploads/../etc/passwd" bypasses this check'
    },
    {
      code: `filtered = filename.replace('..', '')
path = '/uploads/' + filtered`,
      correct: false,
      explanation: 'Simple filtering bypassed by encoded %2e%2e sequences'
    },
    {
      code: `if '/' in filename:
    raise Error('Invalid')
path = '/uploads/' + filename`,
      correct: false,
      explanation: 'Blocking / helps but \\ works on Windows'
    },
    {
      code: `decoded = urllib.parse.unquote(filename)
path = '/uploads/' + decoded`,
      correct: false,
      explanation: 'URL decoding enables %2e%2e%2f to become ../'
    },
    {
      code: `if len(filename) > 20:
    raise Error('Too long')
path = '/uploads/' + filename`,
      correct: false,
      explanation: 'Length limits don\'t prevent short traversal like "../etc"'
    },
    {
      code: `lower = filename.lower()
path = '/uploads/' + lower`,
      correct: false,
      explanation: 'Case conversion doesn\'t prevent "../etc/passwd"'
    },
    {
      code: `if 'script' in filename:
    raise Error('Invalid')
path = '/uploads/' + filename`,
      correct: false,
      explanation: 'Keyword filtering irrelevant to path traversal attacks'
    },
    {
      code: `trimmed = filename.strip()
path = '/uploads/' + trimmed`,
      correct: false,
      explanation: 'Whitespace removal doesn\'t prevent path traversal'
    }
  ]
}