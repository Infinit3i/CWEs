import type { Exercise } from '@/data/exercises'

/**
 * CWE-79 Cross-Site Scripting - DOM-Based XSS
 * Based on client-side DOM manipulation vulnerabilities
 */
export const cwe79Dom: Exercise = {
  cweId: 'CWE-79',
  name: 'Cross-Site Scripting - URL Parameter Display',

  vulnerableFunction: `function displaySearchResults() {
  const urlParams = new URLSearchParams(window.location.search);
  const searchQuery = urlParams.get('q') || '';
  const category = urlParams.get('category') || 'all';

  if (searchQuery) {
    const resultsDiv = document.getElementById('search-results');
    resultsDiv.innerHTML = \`
      <h2>Search Results for: \${searchQuery}</h2>
      <p>Category: \${category}</p>
      <div class="results">Searching...</div>
    \`;

    // Perform actual search
    performSearch(searchQuery, category);
  }
}`,

  vulnerableLine: `resultsDiv.innerHTML = \`<h2>Search Results for: \${searchQuery}</h2><p>Category: \${category}</p><div class="results">Searching...</div>\`;`,

  options: [
    {
      code: `const resultsDiv = document.getElementById('search-results');
const heading = document.createElement('h2');
heading.textContent = 'Search Results for: ' + searchQuery;
const categoryP = document.createElement('p');
categoryP.textContent = 'Category: ' + category;
const resultsContainer = document.createElement('div');
resultsContainer.className = 'results';
resultsContainer.textContent = 'Searching...';
resultsDiv.innerHTML = '';
resultsDiv.appendChild(heading);
resultsDiv.appendChild(categoryP);
resultsDiv.appendChild(resultsContainer);`,
      correct: true,
      explanation: `Correct! This creates DOM elements programmatically and uses textContent to safely insert URL parameters. Even if URL contains ?q=<script>alert('XSS')</script>, it will be displayed as plain text rather than executed as JavaScript.`
    },
    // DOM-based XSS vulnerabilities
    {
      code: `resultsDiv.innerHTML = \`<h2>Search Results for: \${searchQuery}</h2><p>Category: \${category}</p>\`;`,
      correct: false,
      explanation: 'DOM-based XSS vulnerability: URL parameters are directly inserted into innerHTML without sanitization. An attacker can craft URLs like ?q=<img src=x onerror=alert(document.cookie)> to execute malicious scripts in the victim\'s browser.'
    },
    {
      code: `const sanitizedQuery = searchQuery.replace(/script/gi, '');
resultsDiv.innerHTML = \`<h2>Search Results for: \${sanitizedQuery}</h2>\`;`,
      correct: false,
      explanation: 'Simple keyword filtering is easily bypassed. Attackers can use <img src=x onerror=alert(1)>, <svg onload=alert(1)>, or <iframe src=javascript:alert(1)> which do not contain "script".'
    },
    {
      code: `const encoded = encodeURIComponent(searchQuery);
resultsDiv.innerHTML = \`<h2>Search Results for: \${encoded}</h2>\`;`,
      correct: false,
      explanation: 'URL encoding may help but browsers can decode content in certain contexts. Additionally, URL encoding creates poor user experience for legitimate search queries containing spaces or special characters.'
    },
    {
      code: `const escaped = searchQuery.replace(/</g, '&lt;').replace(/>/g, '&gt;');
resultsDiv.innerHTML = \`<h2>Search Results for: \${escaped}</h2>\`;`,
      correct: false,
      explanation: 'HTML entity encoding prevents some attacks but may not cover all vectors. Event handlers and other injection techniques might still work depending on the context and browser behavior.'
    },
    {
      code: `if (searchQuery.includes('<') || searchQuery.includes('>')) {
  resultsDiv.innerHTML = '<h2>Invalid search query</h2>';
} else {
  resultsDiv.innerHTML = \`<h2>Search Results for: \${searchQuery}</h2>\`;
}`,
      correct: false,
      explanation: 'Character blacklisting is incomplete protection. Attackers can use javascript: URLs, data URLs, or event handlers that do not require angle brackets to execute malicious code.'
    },
    {
      code: `const cleanQuery = searchQuery.substring(0, 50);
resultsDiv.innerHTML = \`<h2>Search Results for: \${cleanQuery}</h2>\`;`,
      correct: false,
      explanation: 'Length limits do not prevent XSS attacks. Short but effective payloads like <img src=x onerror=alert(1)> can execute within character limits and still compromise the application.'
    },
    {
      code: `document.getElementById('search-query').value = searchQuery;
resultsDiv.innerHTML = \`<h2>Search Results for: <span id="query-display"></span></h2>\`;
document.getElementById('query-display').textContent = searchQuery;`,
      correct: false,
      explanation: 'While the final textContent assignment is safe, the initial innerHTML still creates a vulnerable window. The structure should be built safely from the start rather than partially fixed afterward.'
    },
    {
      code: `const template = \`<h2>Search Results for: \${searchQuery.toLowerCase()}</h2>\`;
resultsDiv.innerHTML = template;`,
      correct: false,
      explanation: 'Case conversion does not prevent XSS injection. Lowercase versions of malicious scripts like <img src=x onerror=alert(1)> are still executable by browsers.'
    },
    {
      code: `resultsDiv.innerHTML = '';
const heading = document.createElement('h2');
heading.innerHTML = 'Search Results for: ' + searchQuery;
resultsDiv.appendChild(heading);`,
      correct: false,
      explanation: 'While creating elements programmatically is good practice, using innerHTML on the created element still introduces XSS vulnerability. Should use textContent instead of innerHTML for user data.'
    }
  ]
}