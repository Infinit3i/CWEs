import type { Exercise } from '@/data/exercises'

/**
 * Example CWE-79 exercise using real MITRE demonstrative examples
 * This shows the pattern for using authentic vulnerable code from MITRE
 */
export const cwe79Example: Exercise = {
  cweId: 'CWE-79',
  name: 'Cross-Site Scripting - User Profile Display',

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
      explanation: `Correct! textContent treats the input as plain text, not HTML. Even if username contains <script>alert('XSS')</script>, it will be displayed as literal text rather than executed as JavaScript. The DOM API automatically escapes special characters when using textContent, preventing any script injection.`
    },
    // Real MITRE demonstrative examples as wrong answers
    {
      code: `welcomeDiv.innerHTML = '<div>Welcome, ' + username + '</div>';`,
      correct: false,
      explanation: 'Direct from MITRE: innerHTML with unescaped user input allows script injection. An attacker can inject <script>alert("XSS")</script> via the username parameter.'
    },
    {
      code: `welcomeDiv.innerHTML = '<div>Welcome, ' + username.replace("script", "") + '</div>';`,
      correct: false,
      explanation: 'Case-sensitive filtering from MITRE examples. Bypassed by <SCRIPT> (uppercase) or <scr<script>ipt> (nested tags).'
    },
    {
      code: `welcomeDiv.innerHTML = '<div>Welcome, ' + escape(username) + '</div>';`,
      correct: false,
      explanation: 'JavaScript escape() is for URL encoding, not HTML. Scripts remain executable in HTML context.'
    },
    {
      code: `const encoded = encodeURIComponent(username); welcomeDiv.innerHTML = '<div>Welcome, ' + encoded + '</div>';`,
      correct: false,
      explanation: 'URL encoding prevents some attacks but scripts can still execute when decoded by the browser in certain contexts.'
    },
    {
      code: `welcomeDiv.innerHTML = '<div>Welcome, ' + username.substring(0, 20) + '</div>';`,
      correct: false,
      explanation: 'Length truncation does not prevent XSS. Short payloads like <img src=x onerror=alert(1)> can be very effective.'
    },
    {
      code: `welcomeDiv.innerHTML = '<div>Welcome, ' + username.toLowerCase() + '</div>';`,
      correct: false,
      explanation: 'Case conversion does not prevent script injection. Lowercase <script> tags are still executable.'
    },
    {
      code: `welcomeDiv.innerHTML = '<div>Welcome, ' + username.replace(/[<>]/g, '') + '</div>';`,
      correct: false,
      explanation: 'Removing angle brackets helps but incomplete. Event handlers like onerror= do not need brackets to execute.'
    },
    {
      code: `welcomeDiv.innerHTML = '<div>Welcome, ' + JSON.stringify(username) + '</div>';`,
      correct: false,
      explanation: 'JSON.stringify adds quotes but the result can still contain executable JavaScript in HTML context.'
    },
    {
      code: `const cleaned = username.replace(/javascript:/gi, ''); welcomeDiv.innerHTML = '<div>Welcome, ' + cleaned + '</div>';`,
      correct: false,
      explanation: 'Filtering specific protocols is insufficient. Many XSS vectors do not use javascript: protocol (e.g., event handlers).'
    }
  ]
  // CWE data automatically fetched from MITRE API when exercise loads
}