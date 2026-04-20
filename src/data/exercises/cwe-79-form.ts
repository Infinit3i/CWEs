import type { Exercise } from '@/data/exercises'

/**
 * CWE-79 Cross-Site Scripting - Form Input Reflection
 * Based on MITRE examples of reflected XSS in form processing
 */
export const cwe79Form: Exercise = {
  cweId: 'CWE-79',
  name: 'Cross-Site Scripting - Contact Form Validation',

  vulnerableFunction: `function validateAndShowForm(formData) {
  const errors = [];
  const name = formData.get('name') || '';
  const email = formData.get('email') || '';
  const message = formData.get('message') || '';

  // Validate inputs
  if (name.length < 2) errors.push('Name must be at least 2 characters');
  if (!email.includes('@')) errors.push('Please enter a valid email');
  if (message.length < 10) errors.push('Message must be at least 10 characters');

  const statusDiv = document.getElementById('form-status');

  if (errors.length > 0) {
    statusDiv.innerHTML = \`
      <div class="error">
        <h4>Please fix the following errors:</h4>
        <ul>\${errors.map(err => \`<li>\${err}</li>\`).join('')}</ul>
        <p>You entered: Name="\${name}", Email="\${email}"</p>
      </div>
    \`;
  } else {
    statusDiv.innerHTML = \`<div class="success">Thank you \${name}! Your message has been sent.</div>\`;
  }
}`,

  vulnerableLine: `<p>You entered: Name="\${name}", Email="\${email}"</p>`,

  options: [
    {
      code: `const summary = document.createElement('p');
summary.textContent = \`You entered: Name="\${name}", Email="\${email}"\`;
statusDiv.appendChild(summary);`,
      correct: true,
      explanation: `Use textContent instead of innerHTML for user data`
    },
    // Form reflection XSS vulnerabilities
    {
      code: `statusDiv.innerHTML = \`<p>Name: \${name}, Email: \${email}</p>\`;`,
      correct: false,
      explanation: 'innerHTML allows `<script>` injection - executes malicious code'
    },
    {
      code: `const clean = name.replace(/<script>/gi, '');
statusDiv.innerHTML = \`<p>Name: \${clean}</p>\`;`,
      correct: false,
      explanation: 'Removing `<script>` is incomplete - `<img onerror>` bypasses filter'
    },
    {
      code: `const short = email.substring(0, 50);
statusDiv.innerHTML = \`<p>Email: \${short}</p>\`;`,
      correct: false,
      explanation: 'Length limits don\'t prevent XSS - short payloads work'
    },
    {
      code: `const filtered = name.replace(/[<>]/g, '');
statusDiv.innerHTML = \`<p>Name: \${filtered}</p>\`;`,
      correct: false,
      explanation: 'Removing `<>` helps but incomplete - `onerror` works without brackets'
    },
    {
      code: `const encoded = encodeURIComponent(name);
statusDiv.innerHTML = \`<p>Name: \${encoded}</p>\`;`,
      correct: false,
      explanation: 'URL encoding is for HTTP, not HTML display'
    },
    {
      code: `if (name.includes('script')) {
  statusDiv.innerHTML = '<p>Invalid input</p>';
} else {
  statusDiv.innerHTML = \`<p>Name: \${name}</p>\`;
}`,
      correct: false,
      explanation: 'Keyword blacklisting bypassed by `<img onerror>` and others'
    },
    {
      code: `const escaped = name.replace(/</g, '&lt;').replace(/>/g, '&gt;');
statusDiv.innerHTML = \`<p>Name: \${escaped}</p>\`;`,
      correct: false,
      explanation: 'Manual HTML encoding is error-prone - use textContent instead'
    },
    {
      code: `const nameDiv = document.createElement('div');
nameDiv.innerHTML = 'Name: ' + name;
statusDiv.appendChild(nameDiv);`,
      correct: false,
      explanation: 'innerHTML with user data is still vulnerable - use textContent'
    },
    {
      code: `const template = document.createElement('template');
template.innerHTML = \`<p>Name: \${name}</p>\`;
statusDiv.appendChild(template.content.cloneNode(true));`,
      correct: false,
      explanation: 'Templates with innerHTML are still vulnerable - use textContent'
    }
  ]
}