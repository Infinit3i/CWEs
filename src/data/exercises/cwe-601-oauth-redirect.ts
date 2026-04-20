import type { Exercise } from '@/data/exercises'

/**
 * CWE-601: URL Redirection to Untrusted Site (Open Redirect)
 * Scenario: OAuth callback redirection handling
 * Based on MITRE demonstrative examples and real-world OAuth vulnerabilities
 */
export const cwe601OauthRedirect: Exercise = {
  cweId: 'CWE-601',
  name: 'Open Redirect - OAuth Callback Handler',
  language: 'JavaScript',

  vulnerableFunction: `function handleOAuthCallback(authCode, state) {
  // Verify auth code with provider
  const tokenResponse = exchangeCodeForToken(authCode);

  if (tokenResponse.success) {
    // Extract redirect URL from state parameter
    const redirectUrl = decodeURIComponent(state);

    // Set authentication cookie
    setAuthCookie(tokenResponse.accessToken);

    // Redirect user to originally requested page
    window.location.href = redirectUrl;
  } else {
    showError('Authentication failed');
  }
}`,

  vulnerableLine: `window.location.href = redirectUrl;`,

  options: [
    {
      code: `const allowedDomains = ['myapp.com', 'api.myapp.com'];
const url = new URL(redirectUrl);
if (allowedDomains.includes(url.hostname)) {
  window.location.href = redirectUrl;
} else {
  window.location.href = '/dashboard';
}`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    // Real MITRE demonstrative examples as wrong answers
    {
      code: `window.location.href = redirectUrl;`,
      correct: false,
      explanation: 'Unvalidated redirect allows attackers to send users to malicious sites. An attacker could craft a link like "myapp.com/oauth?state=http://phishing-site.com" to steal credentials.'
    },
    {
      code: `if (!redirectUrl.includes('javascript:')) { window.location.href = redirectUrl; }`,
      correct: false,
      explanation: 'Blacklisting approach from MITRE examples. Only blocks javascript: protocol but allows http://evil.com redirects for phishing attacks.'
    },
    {
      code: `const safeUrl = redirectUrl.replace(/[<>"']/g, ''); window.location.href = safeUrl;`,
      correct: false,
      explanation: 'HTML character filtering does not prevent open redirects. The URL http://malicious.com contains no HTML characters but still redirects to an attacker-controlled site.'
    },
    {
      code: `if (redirectUrl.startsWith('/')) { window.location.href = redirectUrl; } else { window.location.href = 'https://myapp.com' + redirectUrl; }`,
      correct: false,
      explanation: 'Relative path checking is incomplete. Attackers can bypass with URLs like "//evil.com" which browsers interpret as "https://evil.com" due to protocol-relative URL handling.'
    },
    {
      code: `if (redirectUrl.indexOf('http') === -1) { window.location.href = redirectUrl; } else { window.location.href = '/dashboard'; }`,
      correct: false,
      explanation: 'Protocol filtering is insufficient. URLs like "//attacker.com" or "ftp://malicious.com" can still redirect to untrusted sites without containing "http".'
    },
    {
      code: `const decoded = atob(redirectUrl); window.location.href = decoded;`,
      correct: false,
      explanation: 'Base64 decoding does not validate the destination. Attackers can simply encode "http://evil.com" as base64 to bypass simple checks while still achieving redirection.'
    },
    {
      code: `if (redirectUrl.length < 100) { window.location.href = redirectUrl; } else { window.location.href = '/dashboard'; }`,
      correct: false,
      explanation: 'Length validation does not prevent malicious redirects. Short URLs like "http://evil.co" or "//bad.io" can still redirect to attacker-controlled sites.'
    },
    {
      code: `const sanitized = redirectUrl.toLowerCase(); window.location.href = sanitized;`,
      correct: false,
      explanation: 'Case conversion does not prevent open redirects. Converting "HTTP://EVIL.COM" to "http://evil.com" still results in redirection to an attacker-controlled site.'
    },
    {
      code: `if (!redirectUrl.includes('evil') && !redirectUrl.includes('malicious')) { window.location.href = redirectUrl; }`,
      correct: false,
      explanation: 'Keyword blacklisting is easily bypassed. Attackers can use domains like "phishing.com" or "fake-bank.net" that do not contain the blocked keywords but are still malicious.'
    }
  ]
}