import type { Exercise } from '@/data/exercises'

/**
 * CWE-79 Cross-Site Scripting - Stored XSS
 * Based on MITRE demonstrative examples for stored XSS vulnerabilities
 */
export const cwe79Stored: Exercise = {
  cweId: 'CWE-79',
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
commentDiv.className = 'comment';
const authorSpan = document.createElement('strong');
authorSpan.textContent = comment.author;
const textSpan = document.createElement('span');
textSpan.textContent = ': ' + comment.text;
const timeSpan = document.createElement('span');
timeSpan.className = 'timestamp';
timeSpan.textContent = comment.timestamp;
commentDiv.appendChild(authorSpan);
commentDiv.appendChild(textSpan);
commentDiv.appendChild(timeSpan);
document.getElementById('comments').appendChild(commentDiv);`,
      correct: true,
      explanation: `Correct! This creates DOM elements programmatically and uses textContent to safely insert user data. Even if comment.text contains malicious scripts like <script>alert('XSS')</script>, they will be treated as plain text and not executed.`
    },
    // MITRE demonstrative examples as wrong answers
    {
      code: `const commentHtml = \`<div class="comment"><strong>\${comment.author}</strong>: \${comment.text}</div>\`;
document.getElementById('comments').innerHTML += commentHtml;`,
      correct: false,
      explanation: 'Direct from MITRE: This is stored XSS where malicious scripts in comment.text get saved to the database and executed every time the page loads. An attacker can inject <script>document.cookie="stolen="+document.cookie</script> to steal session cookies from all visitors.'
    },
    {
      code: `const sanitized = comment.text.replace(/<script>/gi, '');
const commentHtml = \`<div class="comment"><strong>\${comment.author}</strong>: \${sanitized}</div>\`;
document.getElementById('comments').innerHTML += commentHtml;`,
      correct: false,
      explanation: 'From MITRE examples: Simple script tag removal is insufficient. Attackers can bypass with <img src=x onerror=alert(1)>, <svg onload=alert(1)>, or nested tags like <scr<script>ipt>alert(1)</script>.'
    },
    {
      code: `const escaped = comment.text.replace(/</g, '&lt;').replace(/>/g, '&gt;');
const commentHtml = \`<div class="comment"><strong>\${comment.author}</strong>: \${escaped}</div>\`;
document.getElementById('comments').innerHTML += commentHtml;`,
      correct: false,
      explanation: 'While HTML entity encoding helps prevent some XSS, using innerHTML can still be dangerous if the author field is not similarly encoded or if there are other injection points in the template.'
    },
    {
      code: `const encoded = encodeURIComponent(comment.text);
const commentHtml = \`<div class="comment"><strong>\${comment.author}</strong>: \${encoded}</div>\`;
document.getElementById('comments').innerHTML += commentHtml;`,
      correct: false,
      explanation: 'URL encoding is not appropriate for HTML context. While it may prevent some attacks, the browser may decode the content in certain contexts, and URL encoding creates poor user experience for legitimate content.'
    },
    {
      code: `const cleaned = comment.text.substring(0, 100);
const commentHtml = \`<div class="comment"><strong>\${comment.author}</strong>: \${cleaned}</div>\`;
document.getElementById('comments').innerHTML += commentHtml;`,
      correct: false,
      explanation: 'Length truncation does not prevent XSS. Short but effective payloads like <img src=x onerror=alert(1)> can execute malicious code within character limits.'
    },
    {
      code: `const filtered = comment.text.replace(/javascript:/gi, '');
const commentHtml = \`<div class="comment"><strong>\${comment.author}</strong>: \${filtered}</div>\`;
document.getElementById('comments').innerHTML += commentHtml;`,
      correct: false,
      explanation: 'Filtering specific protocols is insufficient. Many XSS vectors do not use javascript: URLs, such as event handlers (onerror=), data URLs, or direct script injection.'
    },
    {
      code: `const safe = comment.text.replace(/[<>"']/g, '');
const commentHtml = \`<div class="comment"><strong>\${comment.author}</strong>: \${safe}</div>\`;
document.getElementById('comments').innerHTML += commentHtml;`,
      correct: false,
      explanation: 'Removing HTML special characters helps but is incomplete. Event handlers can execute without some of these characters, and removing quotes/brackets may not prevent all injection vectors.'
    },
    {
      code: `const template = document.querySelector('#comment-template');
const clone = template.content.cloneNode(true);
clone.querySelector('.author').innerHTML = comment.author;
clone.querySelector('.text').innerHTML = comment.text;
document.getElementById('comments').appendChild(clone);`,
      correct: false,
      explanation: 'While using templates is a good practice, this still uses innerHTML to set user content, making it vulnerable to XSS. The template approach provides structure but doesn\'t solve the injection vulnerability.'
    },
    {
      code: `const commentHtml = \`<div class="comment"><strong>\${DOMPurify.sanitize(comment.author)}</strong>: \${comment.text}</div>\`;
document.getElementById('comments').innerHTML += commentHtml;`,
      correct: false,
      explanation: 'While DOMPurify sanitizes the author field, comment.text remains unsanitized and vulnerable to XSS injection. Partial sanitization creates a false sense of security while leaving attack vectors open.'
    }
  ]
}