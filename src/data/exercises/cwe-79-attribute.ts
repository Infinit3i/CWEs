import type { Exercise } from '@/data/exercises'

/**
 * CWE-79 Cross-Site Scripting - Attribute-Based XSS
 * Based on MITRE examples of XSS in HTML attributes
 */
export const cwe79Attribute: Exercise = {
  cweId: 'CWE-79',
  name: 'Cross-Site Scripting - Profile Image Display',

  vulnerableFunction: `function displayUserProfile(userProfile) {
  const profileContainer = document.getElementById('profile');
  const imageUrl = userProfile.avatarUrl || '/images/default-avatar.png';
  const altText = userProfile.name || 'User Avatar';

  const profileHtml = \`
    <div class="profile-card">
      <img src="\${imageUrl}" alt="\${altText}" class="avatar">
      <h3>\${userProfile.name}</h3>
      <p title="\${userProfile.bio}">\${userProfile.bio}</p>
    </div>
  \`;

  profileContainer.innerHTML = profileHtml;
  return profileHtml;
}`,

  vulnerableLine: `<img src="\${imageUrl}" alt="\${altText}" class="avatar">`,

  options: [
    {
      code: `const profileDiv = document.createElement('div');
profileDiv.className = 'profile-card';
const img = document.createElement('img');
img.src = imageUrl;
img.alt = altText;
img.className = 'avatar';
const h3 = document.createElement('h3');
h3.textContent = userProfile.name;
const p = document.createElement('p');
p.textContent = userProfile.bio;
p.title = userProfile.bio;
profileDiv.appendChild(img);
profileDiv.appendChild(h3);
profileDiv.appendChild(p);
profileContainer.innerHTML = '';
profileContainer.appendChild(profileDiv);`,
      correct: true,
      explanation: `Correct! This creates DOM elements programmatically and uses proper property assignment for attributes. The browser automatically handles escaping when setting element properties, preventing XSS injection through image URLs or alt text.`
    },
    // Attribute-based XSS vulnerabilities
    {
      code: `const profileHtml = \`<img src="\${imageUrl}" alt="\${altText}" class="avatar">\`;
profileContainer.innerHTML = profileHtml;`,
      correct: false,
      explanation: 'Attribute-based XSS: User-controlled data in HTML attributes can break out of the attribute context. An attacker can inject avatarUrl: "x\" onerror=\"alert(document.cookie)" to execute JavaScript when the image fails to load.'
    },
    {
      code: `const cleanUrl = imageUrl.replace(/javascript:/gi, '');
const profileHtml = \`<img src="\${cleanUrl}" alt="\${altText}">\`;
profileContainer.innerHTML = profileHtml;`,
      correct: false,
      explanation: 'Filtering only javascript: URLs is insufficient. Attackers can use data:text/html,<script>alert(1)</script> or break out of the attribute with quote characters to inject event handlers.'
    },
    {
      code: `const encodedUrl = encodeURIComponent(imageUrl);
const profileHtml = \`<img src="\${encodedUrl}" alt="\${altText}">\`;
profileContainer.innerHTML = profileHtml;`,
      correct: false,
      explanation: 'URL encoding breaks legitimate image URLs and may not prevent all attribute-based attacks. Attackers can still manipulate the alt attribute or use other injection vectors not covered by URL encoding.'
    },
    {
      code: `const safeUrl = imageUrl.startsWith('http') ? imageUrl : '/images/default.png';
const profileHtml = \`<img src="\${safeUrl}" alt="\${altText}">\`;
profileContainer.innerHTML = profileHtml;`,
      correct: false,
      explanation: 'URL validation helps but doesn\'t prevent attribute escape attacks. An attacker can use altText: "avatar\" onload=\"alert(1)" to break out of the alt attribute and inject event handlers.'
    },
    {
      code: `const escapedAlt = altText.replace(/"/g, '&quot;');
const profileHtml = \`<img src="\${imageUrl}" alt="\${escapedAlt}">\`;
profileContainer.innerHTML = profileHtml;`,
      correct: false,
      explanation: 'While quote escaping helps prevent attribute escape, the imageUrl parameter remains vulnerable. Attackers can still inject malicious URLs or use single quotes if not properly handled.'
    },
    {
      code: `if (imageUrl.includes('<') || imageUrl.includes('>')) {
  imageUrl = '/images/default.png';
}
const profileHtml = \`<img src="\${imageUrl}" alt="\${altText}">\`;
profileContainer.innerHTML = profileHtml;`,
      correct: false,
      explanation: 'Filtering angle brackets doesn\'t prevent attribute-based XSS. Attackers can break out of attributes using quotes and inject event handlers without using < or > characters.'
    },
    {
      code: `const img = new Image();
img.src = imageUrl;
img.alt = altText;
profileContainer.innerHTML = \`<div class="profile-card">\${img.outerHTML}</div>\`;`,
      correct: false,
      explanation: 'While creating the Image object safely sets properties, using outerHTML in innerHTML still creates XSS risk if other parts of the template contain unsanitized user data.'
    },
    {
      code: `const template = \`<img src="\${imageUrl.substring(0, 100)}" alt="\${altText.substring(0, 50)}">\`;
profileContainer.innerHTML = template;`,
      correct: false,
      explanation: 'Length truncation does not prevent attribute-based XSS. Short payloads like "x\" onerror=\"alert(1)" can be very effective within character limits for breaking out of attributes.'
    },
    {
      code: `const profileHtml = \`<img src="\${imageUrl}" alt="\${altText.toLowerCase()}" class="avatar">\`;
profileContainer.innerHTML = profileHtml;`,
      correct: false,
      explanation: 'Case conversion does not prevent attribute escape attacks. Lowercase event handlers like "avatar\" onload=\"alert(1)" are still executable and can break out of the alt attribute.'
    }
  ]
}