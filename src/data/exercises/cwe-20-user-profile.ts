import type { Exercise } from '@/data/exercises'

export const cwe20UserProfile: Exercise = {
  cweId: 'CWE-20',
  name: 'Improper Input Validation - User Profile Update',
  language: 'JavaScript',

  vulnerableFunction: `function updateUserProfile(profileData) {
  // Extract user input
  const birthday = profileData.birthday;
  const homepage = profileData.homepage;

  // Generate profile HTML
  const profileHTML = \`
    <div class="profile">
      <p>Birthday: \${birthday}</p>
      <p>Homepage: <a href="\${homepage}">Visit Profile</a></p>
    </div>
  \`;

  // Save to user's profile page
  saveProfileHTML(profileHTML);

  return { success: true, profile: profileHTML };
}`,

  vulnerableLine: `<p>Birthday: \${birthday}</p>`,

  options: [
    {
      code: `const safeBirthday = escapeHTML(birthday); const safeHomepage = escapeHTML(homepage);`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    {
      code: `<p>Birthday: \${birthday}</p>`,
      correct: false,
      explanation: 'MITRE unescaped input pattern: User data directly inserted into HTML without validation. Attacker can inject <script>alert("XSS")</script> in birthday field to execute JavaScript, steal cookies, or perform actions as the user.'
    },
    {
      code: `const birthday = profileData.birthday.substring(0, 50);`,
      correct: false,
      explanation: 'Length truncation does not prevent injection. Short malicious payloads like <script>evil()</script> or <img src=x onerror=alert(1)> can be very effective within character limits.'
    },
    {
      code: `const birthday = profileData.birthday.replace('<script>', '');`,
      correct: false,
      explanation: 'Specific tag filtering is insufficient. Attackers can use <SCRIPT> (case), <img onerror=>, event handlers, or nested tags like <scr<script>ipt> to bypass this filter.'
    },
    {
      code: `const birthday = profileData.birthday.toLowerCase();`,
      correct: false,
      explanation: 'Case conversion does not prevent injection. Lowercase <script> tags and event handlers like onclick= remain fully functional for executing malicious JavaScript.'
    },
    {
      code: `if (birthday.includes('<') || birthday.includes('>')) { throw new Error('Invalid input'); }`,
      correct: false,
      explanation: 'Angle bracket detection helps but incomplete. Event handlers like onclick="malicious()" and javascript: URLs can execute without angle brackets.'
    },
    {
      code: `const birthday = profileData.birthday.replace(/script/gi, '');`,
      correct: false,
      explanation: 'Script keyword filtering misses many injection vectors like <img onerror=>, <svg onload=>, javascript: URLs, and data URIs that can execute malicious code.'
    },
    {
      code: `const birthday = encodeURIComponent(profileData.birthday);`,
      correct: false,
      explanation: 'URL encoding prevents some attacks but may be decoded by browser in certain contexts. HTML entities are more appropriate for HTML content protection.'
    },
    {
      code: `try { const profileHTML = generateHTML(birthday, homepage); } catch(e) { return {error: 'Invalid profile data'}; }`,
      correct: false,
      explanation: 'Exception handling does not validate input. Malicious content is still processed and may execute before any error handling can prevent the injection attack.'
    },
    {
      code: `const birthday = JSON.stringify(profileData.birthday);`,
      correct: false,
      explanation: 'JSON.stringify adds quotes but the result can still contain executable JavaScript when inserted into HTML context without proper HTML escaping.'
    }
  ]
}