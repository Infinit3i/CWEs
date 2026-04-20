import type { Exercise } from '@/data/exercises'

/**
 * CWE-601: URL Redirection to Untrusted Site (Open Redirect)
 * Scenario: Mobile app deep link handler
 * Based on MITRE patterns for mobile redirect vulnerabilities
 */
export const cwe601MobileApp: Exercise = {
  cweId: 'CWE-601',
  name: 'Open Redirect - Mobile Deep Link Handler',

  vulnerableFunction: `// React Native deep link handler
import { Linking } from 'react-native';

function handleDeepLink(url) {
  const parsedUrl = new URL(url);
  const action = parsedUrl.searchParams.get('action');
  const redirect = parsedUrl.searchParams.get('redirect');

  switch (action) {
    case 'login':
      // Perform authentication
      authenticateUser()
        .then(success => {
          if (success && redirect) {
            // Redirect to requested page after login
            Linking.openURL(redirect);
          } else {
            navigateToHome();
          }
        });
      break;

    case 'share':
      const content = parsedUrl.searchParams.get('content');
      showShareDialog(content, redirect);
      break;

    default:
      navigateToHome();
  }
}`,

  vulnerableLine: `Linking.openURL(redirect);`,

  options: [
    {
      code: `const allowedSchemes = ['myapp://', 'https://myapp.com'];
const isAllowed = allowedSchemes.some(scheme => redirect.startsWith(scheme));
if (isAllowed) {
  Linking.openURL(redirect);
} else {
  navigateToHome();
}`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    // Real MITRE demonstrative examples adapted for mobile
    {
      code: `Linking.openURL(redirect);`,
      correct: false,
      explanation: 'Direct from MITRE patterns: Unvalidated redirect allows attackers to redirect to malicious apps or phishing sites. Attackers can craft links like "myapp://login?redirect=maliciousapp://steal-data" to hijack user sessions.'
    },
    {
      code: `if (!redirect.includes('://')) { Linking.openURL(redirect); }`,
      correct: false,
      explanation: 'Protocol detection from MITRE examples is flawed. Relative URLs without protocols can still be dangerous, and attackers can use custom schemes that do not contain "://" in harmful ways.'
    },
    {
      code: `const cleaned = redirect.replace(/[^a-zA-Z0-9]/g, ''); Linking.openURL(cleaned);`,
      correct: false,
      explanation: 'Character allowlisting breaks legitimate URLs. Removing all special characters makes valid URLs like "https://myapp.com/dashboard" invalid while not addressing the fundamental redirect validation issue.'
    },
    {
      code: `if (redirect.startsWith('http')) { Linking.openURL(redirect); }`,
      correct: false,
      explanation: 'HTTP protocol checking is insufficient for mobile. Malicious apps can register custom schemes like "evilapp://steal-data" that do not start with "http" but still redirect users to harmful applications.'
    },
    {
      code: `const encoded = encodeURI(redirect); Linking.openURL(encoded);`,
      correct: false,
      explanation: 'URI encoding does not prevent malicious redirects. Encoded malicious URLs like "https://phishing-site.com" remain functional and dangerous after encoding.'
    },
    {
      code: `if (redirect.indexOf('javascript') === -1) { Linking.openURL(redirect); }`,
      correct: false,
      explanation: 'Keyword blacklisting misses mobile-specific threats. While javascript: URLs are blocked, malicious app schemes like "maliciousapp://harvester" or "intent://evil.com" are not prevented.'
    },
    {
      code: `const parsed = redirect.split('?')[0]; Linking.openURL(parsed);`,
      correct: false,
      explanation: 'Query parameter removal does not validate the base URL. URLs like "maliciousapp://steal-data" remain dangerous even without query parameters.'
    },
    {
      code: `if (redirect.length < 50) { Linking.openURL(redirect); }`,
      correct: false,
      explanation: 'Length validation does not prevent malicious redirects. Short URLs like "evil://bad" or "https://evil.co" can still redirect to attacker-controlled destinations.'
    },
    {
      code: `setTimeout(() => Linking.openURL(redirect), 1000);`,
      correct: false,
      explanation: 'Delaying the redirect does not fix the security vulnerability. Adding a timeout before opening a malicious URL does not make it any less dangerous to the user.'
    }
  ]
}