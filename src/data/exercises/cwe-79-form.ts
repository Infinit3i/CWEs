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
      code: `const statusDiv = document.getElementById('form-status');
statusDiv.innerHTML = '';
if (errors.length > 0) {
  const errorDiv = document.createElement('div');
  errorDiv.className = 'error';
  const heading = document.createElement('h4');
  heading.textContent = 'Please fix the following errors:';
  const ul = document.createElement('ul');
  errors.forEach(err => {
    const li = document.createElement('li');
    li.textContent = err;
    ul.appendChild(li);
  });
  const summary = document.createElement('p');
  summary.textContent = \`You entered: Name="\${name}", Email="\${email}"\`;
  errorDiv.appendChild(heading);
  errorDiv.appendChild(ul);
  errorDiv.appendChild(summary);
  statusDiv.appendChild(errorDiv);
} else {
  const successDiv = document.createElement('div');
  successDiv.className = 'success';
  successDiv.textContent = \`Thank you \${name}! Your message has been sent.\`;
  statusDiv.appendChild(successDiv);
}`,
      correct: true,
      explanation: `Correct! This creates DOM elements programmatically and uses textContent to safely insert user data. Even if form fields contain malicious scripts like <script>alert('XSS')</script>, they will be displayed as plain text rather than executed.`
    },
    // Form reflection XSS vulnerabilities
    {
      code: `statusDiv.innerHTML = \`<div class="error"><p>You entered: Name="\${name}", Email="\${email}"</p></div>\`;`,
      correct: false,
      explanation: 'Classic reflected XSS: Form input is directly reflected in the page without sanitization. An attacker can enter name: "<script>alert(document.cookie)</script>" to execute JavaScript and steal session cookies when the error message is displayed.'
    },
    {
      code: `const sanitizedName = name.replace(/<script>/gi, '');
statusDiv.innerHTML = \`<div class="error"><p>Name: \${sanitizedName}</p></div>\`;`,
      correct: false,
      explanation: 'Simple script tag removal is insufficient. Attackers can bypass with <img src=x onerror=alert(1)>, <svg onload=alert(1)>, or use case variations and nested tags like <scr<script>ipt>.'
    },
    {
      code: `const truncatedEmail = email.substring(0, 50);
statusDiv.innerHTML = \`<div class="error"><p>Email: \${truncatedEmail}</p></div>\`;`,
      correct: false,
      explanation: 'Length truncation does not prevent XSS attacks. Effective payloads like <img src=x onerror=alert(1)> are short enough to fit within character limits while still executing malicious code.'
    },
    {
      code: `const filteredName = name.replace(/[<>]/g, '');
statusDiv.innerHTML = \`<div class="error"><p>Name: \${filteredName}</p></div>\`;`,
      correct: false,
      explanation: 'Removing angle brackets helps but is incomplete. Event handlers like onerror=alert(1) can execute without angle brackets, and there may be other injection vectors not covered by this filter.'
    },
    {
      code: `const encodedName = encodeURIComponent(name);
statusDiv.innerHTML = \`<div class="error"><p>Name: \${encodedName}</p></div>\`;`,
      correct: false,
      explanation: 'URL encoding is not appropriate for HTML content display and creates poor user experience. It may also not prevent all XSS vectors depending on how browsers handle the encoded content.'
    },
    {
      code: `if (name.includes('script') || email.includes('script')) {
  statusDiv.innerHTML = '<div class="error">Invalid input detected</div>';
} else {
  statusDiv.innerHTML = \`<div class="error"><p>Name: \${name}, Email: \${email}</p></div>\`;
}`,
      correct: false,
      explanation: 'Keyword blacklisting is easily bypassed. Attackers can use <img src=x onerror=alert(1)>, <iframe src=javascript:alert(1)>, or other XSS vectors that do not contain the word "script".'
    },
    {
      code: `const htmlEscaped = name.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
statusDiv.innerHTML = \`<div class="error"><p>Name: \${htmlEscaped}</p></div>\`;`,
      correct: false,
      explanation: 'While HTML entity encoding is better, it only handles one field (name) and leaves email vulnerable. Additionally, manual encoding is error-prone compared to using safe DOM methods.'
    },
    {
      code: `const nameDiv = document.createElement('div');
nameDiv.innerHTML = 'Name: ' + name;
statusDiv.innerHTML = '';
statusDiv.appendChild(nameDiv);`,
      correct: false,
      explanation: 'While creating elements programmatically is good, using innerHTML with user data still introduces XSS vulnerability. Should use textContent instead of innerHTML for user-controlled content.'
    },
    {
      code: `const template = document.createElement('template');
template.innerHTML = \`<div class="error"><p>Name: \${name}</p></div>\`;
statusDiv.appendChild(template.content.cloneNode(true));`,
      correct: false,
      explanation: 'Template elements still use innerHTML for the template content, making them vulnerable to XSS injection. The template approach provides structure but doesn\'t solve the fundamental injection issue.'
    }
  ]
}