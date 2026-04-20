import type { Exercise } from '@/data/exercises'

/**
 * Example CWE-79 exercise using real MITRE demonstrative examples
 * This shows the pattern for using authentic vulnerable code from MITRE
 */
export const cwe79Example: Exercise = {
  cweId: 'CWE-79',
  name: 'Cross-Site Scripting - User Profile Display',
  language: 'JavaScript',

  vulnerableFunction: `function displayUserWelcome(username) {
  const welcomeDiv = document.getElementById('welcome');
  welcomeDiv.innerHTML = '<div class="header">Welcome, ' + username + '</div>';
  return welcomeDiv;
}`,

  vulnerableLine: `welcomeDiv.innerHTML = '<div class="header">Welcome, ' + username + '</div>';`,

  options: [
    {
      code: `welcomeDiv.textContent = 'Welcome, ' + username;`,
      correct: true,
      explanation: `Use textContent instead of innerHTML for user data`
    },
    // Real MITRE demonstrative examples as wrong answers
    {
      code: `welcomeDiv.innerHTML = 'Welcome, ' + username;`,
      correct: false,
      explanation: 'innerHTML allows `<script>` injection via username'
    },
    {
      code: `const clean = username.replace("script", "");
welcomeDiv.innerHTML = 'Welcome, ' + clean;`,
      correct: false,
      explanation: 'Case-sensitive filter bypassed by `<SCRIPT>` or nested tags'
    },
    {
      code: `welcomeDiv.innerHTML = 'Welcome, ' + escape(username);`,
      correct: false,
      explanation: 'escape() is for URLs - scripts still execute in HTML'
    },
    {
      code: `const encoded = encodeURIComponent(username);
welcomeDiv.innerHTML = 'Welcome, ' + encoded;`,
      correct: false,
      explanation: 'URL encoding incomplete - scripts execute when decoded'
    },
    {
      code: `const short = username.substring(0, 20);
welcomeDiv.innerHTML = 'Welcome, ' + short;`,
      correct: false,
      explanation: 'Length limits don\'t prevent XSS - short payloads work'
    },
    {
      code: `const lower = username.toLowerCase();
welcomeDiv.innerHTML = 'Welcome, ' + lower;`,
      correct: false,
      explanation: 'Case conversion doesn\'t prevent XSS - lowercase scripts work'
    },
    {
      code: `const filtered = username.replace(/[<>]/g, '');
welcomeDiv.innerHTML = 'Welcome, ' + filtered;`,
      correct: false,
      explanation: 'Removing brackets incomplete - `onerror=` works without brackets'
    },
    {
      code: `welcomeDiv.innerHTML = 'Welcome, ' + JSON.stringify(username);`,
      correct: false,
      explanation: 'JSON.stringify incomplete - scripts can execute in HTML context'
    },
    {
      code: `const cleaned = username.replace(/javascript:/gi, '');
welcomeDiv.innerHTML = 'Welcome, ' + cleaned;`,
      correct: false,
      explanation: 'Protocol filtering insufficient - event handlers don\'t use javascript:'
    }
  ]
  // CWE data automatically fetched from MITRE API when exercise loads
}