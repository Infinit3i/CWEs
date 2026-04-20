import type { Exercise } from '@/data/exercises'

/**
 * CWE-601: URL Redirection to Untrusted Site (Open Redirect)
 * Scenario: Password reset flow with return URL
 * Based on MITRE patterns for authentication redirect vulnerabilities
 */
export const cwe601PasswordReset: Exercise = {
  cweId: 'CWE-601',
  name: 'Open Redirect - Password Reset Flow',

  vulnerableFunction: `app.post('/password-reset', async (req, res) => {
  const { email, returnUrl } = req.body;

  try {
    // Validate email exists
    const user = await getUserByEmail(email);
    if (!user) {
      return res.status(400).json({ error: 'Email not found' });
    }

    // Generate reset token
    const resetToken = generateSecureToken();
    await saveResetToken(user.id, resetToken);

    // Create reset link with return URL
    const resetLink = \`https://myapp.com/reset-password?token=\${resetToken}&return=\${encodeURIComponent(returnUrl)}\`;

    // Send email
    await sendResetEmail(user.email, resetLink);

    res.json({ message: 'Password reset email sent' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to process request' });
  }
});

app.get('/reset-password', (req, res) => {
  const { token, return: returnUrl } = req.query;

  if (validateResetToken(token)) {
    // Show password reset form with hidden return URL
    res.render('reset-form', { token, returnUrl });
  } else {
    res.status(400).send('Invalid or expired reset token');
  }
});

app.post('/reset-password', async (req, res) => {
  const { token, newPassword, returnUrl } = req.body;

  if (await resetPassword(token, newPassword)) {
    // Password successfully reset, redirect to return URL
    res.redirect(returnUrl || '/login');
  } else {
    res.status(400).send('Failed to reset password');
  }
});`,

  vulnerableLine: `res.redirect(returnUrl || '/login');`,

  options: [
    {
      code: `const allowedPaths = ['/dashboard', '/profile', '/settings', '/login'];
const urlPath = returnUrl ? new URL(returnUrl, 'https://myapp.com').pathname : '/login';
if (allowedPaths.includes(urlPath)) {
  res.redirect(urlPath);
} else {
  res.redirect('/login');
}`,
      correct: true,
      explanation: `Correct! This implements path allowlisting for post-authentication redirects. By parsing the return URL and extracting only the pathname, then checking it against a predefined list of safe internal paths, we prevent open redirects while maintaining good user experience. Even if an attacker injects "http://evil.com/dashboard", only the "/dashboard" path is extracted and validated, then combined with our trusted domain for safe redirection.`
    },
    // Real MITRE demonstrative examples as wrong answers
    {
      code: `res.redirect(returnUrl || '/login');`,
      correct: false,
      explanation: 'Direct from MITRE patterns: Unvalidated redirect in authentication flow enables phishing attacks. Attackers can intercept password reset emails and modify the return URL to redirect to fake login pages that harvest credentials.'
    },
    {
      code: `if (returnUrl && !returnUrl.includes('evil')) { res.redirect(returnUrl); } else { res.redirect('/login'); }`,
      correct: false,
      explanation: 'Keyword blacklisting from MITRE examples is easily bypassed. Attackers can use domains like "phishing.com" or "fake-myapp.net" that appear legitimate but do not contain blocked keywords.'
    },
    {
      code: `const sanitized = returnUrl ? returnUrl.replace(/[<>"]/g, '') : '/login'; res.redirect(sanitized);`,
      correct: false,
      explanation: 'HTML character filtering does not prevent URL redirection attacks. URLs like "http://attacker.com" contain no HTML characters but still redirect to malicious sites for credential theft.'
    },
    {
      code: `if (returnUrl && returnUrl.startsWith('/')) { res.redirect(returnUrl); } else { res.redirect('/login'); }`,
      correct: false,
      explanation: 'Relative path checking is incomplete. Protocol-relative URLs like "//evil.com" start with "/" but resolve to "https://evil.com" in browsers, enabling phishing attacks.'
    },
    {
      code: `const decoded = returnUrl ? decodeURIComponent(returnUrl) : '/login'; res.redirect(decoded);`,
      correct: false,
      explanation: 'URL decoding does not validate destination safety. Decoding an attacker-supplied URL like "http%3A%2F%2Fevil.com" results in "http://evil.com" which is still a malicious redirect.'
    },
    {
      code: `if (returnUrl && returnUrl.indexOf('myapp.com') > -1) { res.redirect(returnUrl); } else { res.redirect('/login'); }`,
      correct: false,
      explanation: 'Substring checking is vulnerable to bypass. Attackers can use domains like "myapp.com.evil.com" or "evil.com/myapp.com" that contain the trusted string but redirect to attacker-controlled sites.'
    },
    {
      code: `const isValid = returnUrl && /^https?:\/\//.test(returnUrl); if (isValid) { res.redirect(returnUrl); } else { res.redirect('/login'); }`,
      correct: false,
      explanation: 'Protocol validation only checks URL format but not destination. Valid URLs like "https://phishing-site.com" pass this test but still redirect users to credential-harvesting sites.'
    },
    {
      code: `if (returnUrl && returnUrl.length < 100) { res.redirect(returnUrl); } else { res.redirect('/login'); }`,
      correct: false,
      explanation: 'Length validation does not prevent malicious redirects. Short URLs like "http://evil.co" or bit.ly-style shortened links can redirect to phishing sites while staying under length limits.'
    },
    {
      code: `const lowercased = returnUrl ? returnUrl.toLowerCase() : '/login'; res.redirect(lowercased);`,
      correct: false,
      explanation: 'Case normalization does not prevent open redirects. Converting "HTTP://EVIL.COM" to "http://evil.com" still results in a redirect to an attacker-controlled phishing site.'
    }
  ]
}