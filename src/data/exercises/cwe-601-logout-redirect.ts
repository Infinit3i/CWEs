import type { Exercise } from '@/data/exercises'

/**
 * CWE-601: URL Redirection to Untrusted Site (Open Redirect)
 * Scenario: Logout endpoint with destination redirect
 * Based on MITRE patterns for session termination redirects
 */
export const cwe601LogoutRedirect: Exercise = {
  cweId: 'CWE-601',
  name: 'Open Redirect - Logout Redirect Handler',
  language: 'JavaScript',

  vulnerableFunction: `app.post('/logout', (req, res) => {
  const { redirect_uri } = req.body;
  const sessionToken = req.headers.authorization?.replace('Bearer ', '');

  try {
    // Validate session exists
    if (!sessionToken || !isValidSession(sessionToken)) {
      return res.status(401).json({ error: 'Invalid session' });
    }

    // Get user info before destroying session
    const userInfo = getSessionUser(sessionToken);

    // Destroy user session
    destroySession(sessionToken);

    // Clear authentication cookies
    res.clearCookie('auth_token');
    res.clearCookie('session_id');

    // Log logout event
    logUserAction(userInfo.userId, 'logout', {
      timestamp: new Date().toISOString(),
      redirectDestination: redirect_uri
    });

    // Redirect to specified destination or default
    if (redirect_uri) {
      res.redirect(302, redirect_uri);
    } else {
      res.redirect(302, '/login');
    }

  } catch (error) {
    res.status(500).json({ error: 'Logout failed' });
  }
});`,

  vulnerableLine: `res.redirect(302, redirect_uri);`,

  options: [
    {
      code: `const internalPages = ['/login', '/home', '/about', '/contact'];
const publicDomains = ['partner1.com', 'partner2.com'];

try {
  const url = new URL(redirect_uri);
  const isInternal = internalPages.includes(url.pathname);
  const isTrustedDomain = publicDomains.includes(url.hostname);

  if (isInternal || isTrustedDomain) {
    res.redirect(302, redirect_uri);
  } else {
    res.redirect(302, '/login');
  }
} catch {
  res.redirect(302, '/login');
}`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    // Real MITRE demonstrative examples as wrong answers
    {
      code: `res.redirect(302, redirect_uri);`,
      correct: false,
      explanation: 'Unvalidated logout redirect enables session fixation and phishing attacks. Attackers can craft logout links that redirect to fake login pages, tricking users into entering credentials on malicious sites immediately after logout.'
    },
    {
      code: `if (redirect_uri.indexOf('http://') === -1) { res.redirect(302, redirect_uri); } else { res.redirect(302, '/login'); }`,
      correct: false,
      explanation: 'Protocol blacklisting from MITRE examples is incomplete. HTTPS URLs like "https://phishing.com" and protocol-relative URLs like "//evil.com" bypass this check but still redirect to malicious sites.'
    },
    {
      code: `const escaped = redirect_uri.replace(/['"<>]/g, ''); res.redirect(302, escaped);`,
      correct: false,
      explanation: 'Character escaping does not prevent URL redirects. URLs like "http://evil.com" contain no HTML special characters but still redirect users to attacker-controlled phishing pages.'
    },
    {
      code: `if (redirect_uri.includes('.com')) { res.redirect(302, redirect_uri); } else { res.redirect(302, '/login'); }`,
      correct: false,
      explanation: 'Domain pattern matching is unreliable. Many malicious sites use .com domains, and attackers can register domains like "myapp-login.com" that appear legitimate but harvest user credentials.'
    },
    {
      code: `const base64Decoded = atob(redirect_uri); res.redirect(302, base64Decoded);`,
      correct: false,
      explanation: 'Base64 decoding does not validate redirect destinations. Attackers can encode "http://phishing.com" as base64 and still achieve malicious redirects after decoding.'
    },
    {
      code: `if (redirect_uri.charAt(0) === '/') { res.redirect(302, redirect_uri); } else { res.redirect(302, '/login'); }`,
      correct: false,
      explanation: 'Single character checking misses protocol-relative URLs. URLs like "//evil.com" start with "/" but resolve to external malicious sites in browsers.'
    },
    {
      code: `const trimmed = redirect_uri.trim(); if (trimmed !== redirect_uri) { res.redirect(302, '/login'); } else { res.redirect(302, trimmed); }`,
      correct: false,
      explanation: 'Whitespace validation does not address redirect destination. Even properly trimmed URLs like "http://evil.com" can still redirect to malicious sites for credential theft.'
    },
    {
      code: `if (redirect_uri.match(/^[a-zA-Z0-9\/\.\-_:]+$/)) { res.redirect(302, redirect_uri); } else { res.redirect(302, '/login'); }`,
      correct: false,
      explanation: 'Character allowlisting allows malicious URLs. The pattern permits URLs like "http://evil.com" which contain only allowed characters but redirect to attacker-controlled phishing sites.'
    },
    {
      code: `const split = redirect_uri.split('://'); if (split.length === 1) { res.redirect(302, redirect_uri); } else { res.redirect(302, '/login'); }`,
      correct: false,
      explanation: 'Protocol splitting logic is flawed. This only allows URLs without protocols, but relative URLs like "../../../admin" or "//evil.com" can still cause unintended navigation or external redirects.'
    }
  ]
}