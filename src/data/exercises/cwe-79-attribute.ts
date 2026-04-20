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
      code: `const img = document.createElement('img');
img.src = imageUrl;
img.alt = altText;
profileContainer.appendChild(img);`,
      correct: true,
      explanation: `Use createElement and property assignment for safe attributes`
    },
    // Attribute-based XSS vulnerabilities
    {
      code: `profileContainer.innerHTML = \`<img src="\${imageUrl}" alt="\${altText}">\`;`,
      correct: false,
      explanation: 'Attribute injection allows `" onerror="alert()` to escape quotes'
    },
    {
      code: `const clean = imageUrl.replace(/javascript:/gi, '');
profileContainer.innerHTML = \`<img src="\${clean}" alt="\${altText}">\`;`,
      correct: false,
      explanation: 'javascript: filter incomplete - data: URLs and quote escape work'
    },
    {
      code: `const encoded = encodeURIComponent(imageUrl);
profileContainer.innerHTML = \`<img src="\${encoded}" alt="\${altText}">\`;`,
      correct: false,
      explanation: 'URL encoding breaks image URLs - alt attribute still vulnerable'
    },
    {
      code: `const safe = imageUrl.startsWith('http') ? imageUrl : '/default.png';
profileContainer.innerHTML = \`<img src="\${safe}" alt="\${altText}">\`;`,
      correct: false,
      explanation: 'URL validation incomplete - alt text allows quote escape'
    },
    {
      code: `const escaped = altText.replace(/"/g, '&quot;');
profileContainer.innerHTML = \`<img src="\${imageUrl}" alt="\${escaped}">\`;`,
      correct: false,
      explanation: 'Quote escaping incomplete - imageUrl still vulnerable'
    },
    {
      code: `if (imageUrl.includes('<')) {
  imageUrl = '/default.png';
}
profileContainer.innerHTML = \`<img src="\${imageUrl}" alt="\${altText}">\`;`,
      correct: false,
      explanation: 'Angle bracket filter incomplete - quotes escape attributes'
    },
    {
      code: `const img = new Image();
img.src = imageUrl;
profileContainer.innerHTML = \`<div>\${img.outerHTML}</div>\`;`,
      correct: false,
      explanation: 'outerHTML in innerHTML still risky - other template parts vulnerable'
    },
    {
      code: `const short = imageUrl.substring(0, 50);
profileContainer.innerHTML = \`<img src="\${short}" alt="\${altText}">\`;`,
      correct: false,
      explanation: 'Length limits don\'t prevent attribute XSS - short payloads work'
    },
    {
      code: `const lower = altText.toLowerCase();
profileContainer.innerHTML = \`<img src="\${imageUrl}" alt="\${lower}">\`;`,
      correct: false,
      explanation: 'Case conversion doesn\'t prevent attribute escape attacks'
    }
  ]
}