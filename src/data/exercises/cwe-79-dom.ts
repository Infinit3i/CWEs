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
      code: `const heading = document.createElement('h2');
heading.textContent = 'Search Results for: ' + searchQuery;
resultsDiv.appendChild(heading);`,
      correct: true,
      explanation: `Use createElement and textContent for safe DOM manipulation`
    },
    // DOM-based XSS vulnerabilities
    {
      code: `resultsDiv.innerHTML = \`<h2>Search Results for: \${searchQuery}</h2>\`;`,
      correct: false,
      explanation: 'URL params in innerHTML allow `<img onerror>` script execution'
    },
    {
      code: `const clean = searchQuery.replace(/script/gi, '');
resultsDiv.innerHTML = \`<h2>Search Results for: \${clean}</h2>\`;`,
      correct: false,
      explanation: 'Keyword filtering bypassed by `<img onerror>` and others'
    },
    {
      code: `const encoded = encodeURIComponent(searchQuery);
resultsDiv.innerHTML = \`<h2>Search Results for: \${encoded}</h2>\`;`,
      correct: false,
      explanation: 'URL encoding creates poor UX - use textContent instead'
    },
    {
      code: `const escaped = searchQuery.replace(/</g, '&lt;').replace(/>/g, '&gt;');
resultsDiv.innerHTML = \`<h2>Results: \${escaped}</h2>\`;`,
      correct: false,
      explanation: 'HTML encoding incomplete - event handlers may still work'
    },
    {
      code: `if (searchQuery.includes('<')) {
  resultsDiv.innerHTML = '<h2>Invalid query</h2>';
} else {
  resultsDiv.innerHTML = \`<h2>Results: \${searchQuery}</h2>\`;
}`,
      correct: false,
      explanation: 'Character blacklisting incomplete - event handlers don\'t need brackets'
    },
    {
      code: `const short = searchQuery.substring(0, 50);
resultsDiv.innerHTML = \`<h2>Results: \${short}</h2>\`;`,
      correct: false,
      explanation: 'Length limits don\'t prevent XSS - short payloads work'
    },
    {
      code: `resultsDiv.innerHTML = \`<h2>Results: <span id="display"></span></h2>\`;
document.getElementById('display').textContent = searchQuery;`,
      correct: false,
      explanation: 'Mixed innerHTML and textContent creates vulnerability window'
    },
    {
      code: `const lower = searchQuery.toLowerCase();
resultsDiv.innerHTML = \`<h2>Results: \${lower}</h2>\`;`,
      correct: false,
      explanation: 'Case conversion doesn\'t prevent XSS - lowercase scripts work'
    },
    {
      code: `const heading = document.createElement('h2');
heading.innerHTML = 'Results: ' + searchQuery;
resultsDiv.appendChild(heading);`,
      correct: false,
      explanation: 'innerHTML on created element still vulnerable - use textContent'
    }
  ]
}