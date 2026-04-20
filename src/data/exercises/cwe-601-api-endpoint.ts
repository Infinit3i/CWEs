import type { Exercise } from '@/data/exercises'

/**
 * CWE-601: URL Redirection to Untrusted Site (Open Redirect)
 * Scenario: API endpoint for URL shortening service
 * Based on MITRE patterns for web service redirects
 */
export const cwe601ApiEndpoint: Exercise = {
  cweId: 'CWE-601',
  name: 'Open Redirect - URL Shortener API',
  language: 'JavaScript',

  vulnerableFunction: `app.post('/api/shorten', async (req, res) => {
  const { originalUrl, customAlias } = req.body;

  // Validate custom alias
  if (customAlias && await isAliasExists(customAlias)) {
    return res.status(400).json({ error: 'Alias already exists' });
  }

  // Generate short URL
  const shortId = customAlias || generateShortId();
  await saveUrlMapping(shortId, originalUrl);

  res.json({
    shortUrl: \`https://short.ly/\${shortId}\`,
    originalUrl: originalUrl
  });
});

app.get('/:shortId', async (req, res) => {
  const mapping = await getUrlMapping(req.params.shortId);

  if (mapping) {
    res.redirect(302, mapping.originalUrl);
  } else {
    res.status(404).send('Short URL not found');
  }
});`,

  vulnerableLine: `res.redirect(302, mapping.originalUrl);`,

  options: [
    {
      code: `const allowedProtocols = ['http:', 'https:'];
const url = new URL(mapping.originalUrl);
if (allowedProtocols.includes(url.protocol)) {
  res.redirect(302, mapping.originalUrl);
} else {
  res.status(400).send('Invalid redirect URL');
}`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    // Real MITRE demonstrative examples as wrong answers
    {
      code: `res.redirect(302, mapping.originalUrl);`,
      correct: false,
      explanation: 'Unvalidated redirect accepts any URL stored in database. Attackers can create short URLs pointing to phishing sites, malware, or javascript: schemes to execute code.'
    },
    {
      code: `if (mapping.originalUrl.includes('http')) { res.redirect(302, mapping.originalUrl); }`,
      correct: false,
      explanation: 'Substring checking from MITRE examples is insufficient. URLs like "javascript:alert(document.cookie)" do not contain "http" but can execute malicious code when redirected.'
    },
    {
      code: `const cleanUrl = mapping.originalUrl.replace(/['"<>]/g, ''); res.redirect(302, cleanUrl);`,
      correct: false,
      explanation: 'Character filtering does not prevent malicious redirects. URLs like "javascript:eval(String.fromCharCode(97,108,101,114,116,40,49,41))" contain no filtered characters but execute code.'
    },
    {
      code: `if (!mapping.originalUrl.startsWith('javascript:')) { res.redirect(302, mapping.originalUrl); }`,
      correct: false,
      explanation: 'Single protocol blacklisting is incomplete. Other dangerous schemes like "data:text/html,<script>alert(1)</script>" or "file:///etc/passwd" can still cause harm.'
    },
    {
      code: `const encoded = encodeURIComponent(mapping.originalUrl); res.redirect(302, encoded);`,
      correct: false,
      explanation: 'URL encoding makes the redirect invalid but does not fix the security issue. The encoded URL will not work as a redirect, breaking legitimate functionality without addressing the root cause.'
    },
    {
      code: `if (mapping.originalUrl.indexOf('.') > -1) { res.redirect(302, mapping.originalUrl); }`,
      correct: false,
      explanation: 'Domain detection is unreliable. URLs like "javascript:alert(1)" or "data:text/html,<script>location.href=//evil.com</script>" do not contain dots but are still dangerous.'
    },
    {
      code: `const parsed = mapping.originalUrl.split('://'); if (parsed[0] === 'https') { res.redirect(302, mapping.originalUrl); }`,
      correct: false,
      explanation: 'Manual protocol parsing is error-prone. This only allows HTTPS but rejects legitimate HTTP URLs, and attackers can bypass with URLs like "https:evil.com" (missing //).'
    },
    {
      code: `if (mapping.originalUrl.match(/^https?:/)) { res.redirect(302, mapping.originalUrl); }`,
      correct: false,
      explanation: 'Regex validation is close but incomplete. The pattern matches "https:" but does not require the // that follows, allowing malformed URLs that may be interpreted unexpectedly by browsers.'
    },
    {
      code: `try { new URL(mapping.originalUrl); res.redirect(302, mapping.originalUrl); } catch { res.status(400).send('Invalid URL'); }`,
      correct: false,
      explanation: 'URL constructor validation only checks format validity. Valid but malicious URLs like "javascript:alert(1)" or "data:text/html,<script>alert(1)</script>" pass this test but are still dangerous.'
    }
  ]
}