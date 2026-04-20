import type { Exercise } from '@/data/exercises'

export const cwe20UrlParameter: Exercise = {
  cweId: 'CWE-20',
  name: 'Improper Input Validation - URL Intent Parameter',
  language: 'JavaScript',

  vulnerableFunction: `function processWebIntent(intentData) {
  // Extract URL from intent extras
  const targetURL = intentData.getStringExtra('URLToOpen');

  // Calculate URL metrics
  const urlLength = targetURL.length;
  const isSecure = targetURL.startsWith('https://');

  // Process URL for navigation
  const processedURL = sanitizeURL(targetURL);

  return {
    url: processedURL,
    length: urlLength,
    secure: isSecure,
    ready: true
  };
}`,

  vulnerableLine: `const urlLength = targetURL.length;`,

  options: [
    {
      code: `if (targetURL !== null && targetURL !== undefined) { const urlLength = targetURL.length; } else { throw new Error('URL parameter required'); }`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    {
      code: `const urlLength = targetURL.length;`,
      correct: false,
      explanation: 'MITRE null parameter pattern: getStringExtra() returns null when URLToOpen parameter not present in intent. Accessing .length on null causes null pointer exception, potentially crashing the application.'
    },
    {
      code: `const urlLength = targetURL?.length || 0;`,
      correct: false,
      explanation: 'Optional chaining prevents crash but continues processing with null URL. This masks the missing parameter issue rather than properly handling the error condition.'
    },
    {
      code: `try { const urlLength = targetURL.length; } catch(e) { const urlLength = 0; }`,
      correct: false,
      explanation: 'Exception handling after null access is reactive. Better to validate parameter existence upfront rather than catching null pointer exceptions.'
    },
    {
      code: `const urlLength = (targetURL || '').length;`,
      correct: false,
      explanation: 'Fallback to empty string prevents crash but continues with invalid state. Missing URL parameter indicates client error that should be handled explicitly.'
    },
    {
      code: `if (typeof targetURL === 'string') { const urlLength = targetURL.length; }`,
      correct: false,
      explanation: 'Type checking helps but null is not a string, so this still does not handle the missing parameter case where getStringExtra returns null.'
    },
    {
      code: `const urlLength = String(targetURL).length;`,
      correct: false,
      explanation: 'String coercion converts null to "null" (4 characters), providing incorrect length calculation and masking the missing parameter issue.'
    },
    {
      code: `if (targetURL) { const urlLength = targetURL.length; }`,
      correct: false,
      explanation: 'Truthy check prevents crash but incomplete handling. Need to properly address missing parameter scenario rather than just skipping processing.'
    },
    {
      code: `const targetURL = intentData.getStringExtra('URLToOpen') || 'about:blank'; const urlLength = targetURL.length;`,
      correct: false,
      explanation: 'Default URL prevents crash but changes application behavior. Missing parameter might indicate client error that should be reported rather than silently handled.'
    },
    {
      code: `const urlLength = targetURL && targetURL.length ? targetURL.length : -1;`,
      correct: false,
      explanation: 'Conditional length calculation avoids crash but returns magic number (-1) that could cause issues in downstream processing expecting valid length values.'
    }
  ]
}