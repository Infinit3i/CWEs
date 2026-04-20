import type { Exercise } from '@/data/exercises'

/**
 * CWE-79 Cross-Site Scripting - Stored XSS
 * Based on MITRE demonstrative examples for stored XSS vulnerabilities
 */
export const cwe79Stored: Exercise = {
  cweId: 'CWE-79',
  language: 'JavaScript',
  name: 'Cross-Site Scripting - User Comment System',

  vulnerableFunction: `function saveAndDisplayComment(commentText, username) {
  // Save comment to database
  const comment = {
    id: generateId(),
    text: commentText,
    author: username,
    timestamp: new Date()
  };

  database.comments.insert(comment);

  // Display the comment immediately
  const commentHtml = \`
    <div class="comment">
      <strong>\${comment.author}</strong>: \${comment.text}
      <span class="timestamp">\${comment.timestamp}</span>
    </div>
  \`;

  document.getElementById('comments').innerHTML += commentHtml;
  return comment;
}`,

  vulnerableLine: `document.getElementById('comments').innerHTML += commentHtml;`,

  options: [
    {
      code: `const commentDiv = document.createElement('div');
commentDiv.textContent = comment.author + ': ' + comment.text;
document.getElementById('comments').appendChild(commentDiv);`,
      correct: true,
      explanation: `Use createElement and textContent for safe comment display`
    },
    // MITRE demonstrative examples as wrong answers
    {
      code: `document.getElementById('comments').innerHTML += \`<div>\${comment.author}: \${comment.text}</div>\`;`,
      correct: false,
      explanation: 'Stored XSS - malicious `<script>` persists and executes for all users'
    },
    {
      code: `const clean = comment.text.replace(/<script>/gi, '');
document.getElementById('comments').innerHTML += \`<div>\${clean}</div>\`;`,
      correct: false,
      explanation: 'Script tag removal incomplete - `<img onerror>` bypasses filter'
    },
    {
      code: `const escaped = comment.text.replace(/</g, '&lt;').replace(/>/g, '&gt;');
document.getElementById('comments').innerHTML += \`<div>\${escaped}</div>\`;`,
      correct: false,
      explanation: 'HTML encoding incomplete - author field still vulnerable'
    },
    {
      code: `const encoded = encodeURIComponent(comment.text);
document.getElementById('comments').innerHTML += \`<div>\${encoded}</div>\`;`,
      correct: false,
      explanation: 'URL encoding wrong for HTML - creates poor user experience'
    },
    {
      code: `const short = comment.text.substring(0, 100);
document.getElementById('comments').innerHTML += \`<div>\${short}</div>\`;`,
      correct: false,
      explanation: 'Length limits don\'t prevent XSS - short payloads work'
    },
    {
      code: `const filtered = comment.text.replace(/javascript:/gi, '');
document.getElementById('comments').innerHTML += \`<div>\${filtered}</div>\`;`,
      correct: false,
      explanation: 'Protocol filtering incomplete - event handlers don\'t use javascript:'
    },
    {
      code: `const safe = comment.text.replace(/[<>"']/g, '');
document.getElementById('comments').innerHTML += \`<div>\${safe}</div>\`;`,
      correct: false,
      explanation: 'Removing special chars incomplete - event handlers still work'
    },
    {
      code: `const template = document.querySelector('#comment-template');
const clone = template.content.cloneNode(true);
clone.querySelector('.text').innerHTML = comment.text;
document.getElementById('comments').appendChild(clone);`,
      correct: false,
      explanation: 'Templates with innerHTML still vulnerable - use textContent'
    },
    {
      code: `const clean = DOMPurify.sanitize(comment.author);
document.getElementById('comments').innerHTML += \`<div>\${clean}: \${comment.text}</div>\`;`,
      correct: false,
      explanation: 'Partial DOMPurify - comment.text still vulnerable to XSS'
    }
  ]
}