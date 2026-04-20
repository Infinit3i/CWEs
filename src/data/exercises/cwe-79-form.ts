import type { Exercise } from '@/data/exercises'

/**
 * CWE-79 Cross-Site Scripting - Form Input Reflection
 * Based on MITRE examples of reflected XSS in form processing
 */
export const cwe79Form: Exercise = {
  cweId: 'CWE-79',
  language: 'JavaScript',
  name: 'Cross-Site Scripting - Contact Form Validation',

  vulnerableFunction: `function displayUserName(name) {
  const div = document.getElementById('greeting');
  div.innerHTML = \`<h2>Welcome \${name}!</h2>\`;
}`,

  vulnerableLine: `div.innerHTML = \`<h2>Welcome \${name}!</h2>\`;`,

  options: [
    {
      code: `div.textContent = \`Welcome \${name}!\`;`,
      correct: true,
      explanation: `textContent treats input as text, not HTML code`
    },
    {
      code: `div.innerHTML = \`<h2>Hello \${name}</h2>\`;`,
      correct: false,
      explanation: 'innerHTML executes user scripts like <script>alert(1)</script>'
    },
    {
      code: `const clean = name.replace(/<script>/gi, '');
div.innerHTML = \`<h2>Welcome \${clean}!</h2>\`;`,
      correct: false,
      explanation: 'Only blocks <script> - <img onerror=alert(1)> still works'
    },
    {
      code: `const short = name.substring(0, 20);
div.innerHTML = \`<h2>Hi \${short}!</h2>\`;`,
      correct: false,
      explanation: 'Length limits don\'t stop XSS - <img onerror=alert(1)> is short'
    },
    {
      code: `const filtered = name.replace(/[<>]/g, '');
div.innerHTML = \`<h2>Welcome \${filtered}!</h2>\`;`,
      correct: false,
      explanation: 'Removing <> helps but incomplete - events like onerror still work'
    },
    {
      code: `const encoded = encodeURIComponent(name);
div.innerHTML = \`<h2>Welcome \${encoded}!</h2>\`;`,
      correct: false,
      explanation: 'URL encoding is for URLs, not HTML content'
    },
    {
      code: `if (name.includes('script')) {
  div.innerHTML = '<h2>Invalid name</h2>';
} else {
  div.innerHTML = \`<h2>Welcome \${name}!</h2>\`;
}`,
      correct: false,
      explanation: 'Keyword filtering bypassed by <img onerror=alert(1)>'
    },
    {
      code: `const escaped = name.replace(/</g, '&lt;');
div.innerHTML = \`<h2>Welcome \${escaped}!</h2>\`;`,
      correct: false,
      explanation: 'Manual escaping is error-prone - use textContent'
    },
    {
      code: `const h2 = document.createElement('h2');
h2.innerHTML = 'Welcome ' + name;
div.appendChild(h2);`,
      correct: false,
      explanation: 'innerHTML with user data is still vulnerable'
    },
    {
      code: `div.outerHTML = \`<div><h2>Welcome \${name}!</h2></div>\`;`,
      correct: false,
      explanation: 'outerHTML has same XSS risk as innerHTML'
    }
  ]
}