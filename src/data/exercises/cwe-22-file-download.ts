import type { Exercise } from '@/data/exercises'

/**
 * CWE-22 exercise - File Download Endpoint
 * Based on MITRE demonstrative examples for path traversal vulnerabilities
 */
export const cwe22FileDownload: Exercise = {
  cweId: 'CWE-22',
  name: 'Path Traversal - File Download Endpoint',
  language: 'Python',

  vulnerableFunction: `from flask import Flask, request, send_file, abort
import os
import os.path

app = Flask(__name__)
UPLOAD_DIR = "/var/www/uploads"

@app.route('/api/download/<filename>')
def download_file(filename):
    # Vulnerable path construction
    file_path = os.path.join(UPLOAD_DIR, filename)

    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True)
    else:
        abort(404, "File not found")`,

  vulnerableLine: `file_path = os.path.join(UPLOAD_DIR, filename)`,

  options: [
    {
      code: `@app.route('/api/download/<filename>')
def download_file(filename):
    # Sanitize filename - remove path components
    safe_name = os.path.basename(filename)
    file_path = os.path.join(UPLOAD_DIR, safe_name)

    # Resolve and validate path stays within upload directory
    resolved_path = os.path.realpath(file_path)
    upload_real = os.path.realpath(UPLOAD_DIR)

    if not resolved_path.startswith(upload_real + os.sep):
        abort(403, "Access denied")

    if os.path.exists(resolved_path):
        return send_file(resolved_path, as_attachment=True)
    else:
        abort(404, "File not found")`,
      correct: true,
      explanation: `Use os.path.basename() and validate resolved path stays within allowed directory`
    },
    {
      code: `const filePath = '/users/cwe/profiles/' + filename;`,
      correct: false,
      explanation: 'String concatenation with user input allows attackers to inject "../../../etc/passwd" to escape the intended directory and access sensitive files.'
    },
    {
      code: `const cleaned = filename.replace('../', ''); const filePath = path.join(__dirname, 'uploads', cleaned);`,
      correct: false,
      explanation: 'Removing only the first instance of "../" fails when attackers provide multiple sequences like "../../../etc/passwd" - after one is stripped, traversal sequences remain.'
    },
    {
      code: `if (filename.startsWith('/uploads/')) { const filePath = filename; }`,
      correct: false,
      explanation: 'MITRE vulnerability: startsWith() validation can be bypassed. A path like "/uploads/../important.dat" passes validation yet the "../" sequence still accesses files outside the directory.'
    },
    {
      code: `const filePath = path.join(__dirname, filename);`,
      correct: false,
      explanation: 'Path joining without base directory validation allows absolute paths. Attackers can supply "/etc/passwd" to bypass directory restrictions entirely.'
    },
    {
      code: `const filtered = filename.replace(/\.\./g, ''); const filePath = path.join(__dirname, 'uploads', filtered);`,
      correct: false,
      explanation: 'Simple regex filtering can be bypassed with encoded sequences like %2e%2e%2f or double-encoded paths that decode after validation.'
    },
    {
      code: `if (filename.includes('/')) { throw new Error('Invalid'); } const filePath = path.join(__dirname, 'uploads', filename);`,
      correct: false,
      explanation: 'Blocking forward slashes helps but is insufficient on Windows systems where backslashes (\\) can also traverse directories.'
    },
    {
      code: `const decoded = decodeURIComponent(filename); const filePath = path.join(__dirname, 'uploads', decoded);`,
      correct: false,
      explanation: 'URL decoding without validation actually increases attack surface by enabling encoded traversal sequences like %2e%2e%2f to become ../'
    },
    {
      code: `if (filename.length > 50) { throw new Error('Too long'); } const filePath = path.join(__dirname, 'uploads', filename);`,
      correct: false,
      explanation: 'Length validation alone is insufficient. Short traversal sequences like "../../../etc" can be very effective within length limits.'
    },
    {
      code: `const sanitized = filename.toLowerCase(); const filePath = path.join(__dirname, 'uploads', sanitized);`,
      correct: false,
      explanation: 'Case conversion does not prevent path traversal. Lowercase "../etc/passwd" sequences are still effective for directory escape.'
    }
  ]
}