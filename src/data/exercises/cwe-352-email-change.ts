import type { Exercise } from '@/data/exercises'

/**
 * CWE-352 exercise - Email Change Endpoint
 * Based on MITRE CSRF attack patterns with auto-submitting forms
 */
export const cwe352EmailChange: Exercise = {
  cweId: 'CWE-352',
  name: 'Cross-Site Request Forgery - Email Change',
  language: 'JavaScript',

  vulnerableFunction: `app.post('/change-email', (req, res) => {
  if (!req.session.userId) {
    return res.redirect('/login');
  }

  const { newEmail } = req.body;
  updateUserEmail(req.session.userId, newEmail);
  res.redirect('/profile?msg=email-updated');
});`,

  vulnerableLine: `app.post('/change-email', (req, res) => {`,

  options: [
    {
      code: `const csrfToken = generateCSRFToken(req.session); app.post('/change-email', (req, res) => { if (req.body._csrf !== req.session.csrfToken) { return res.status(403).send('CSRF token mismatch'); }`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    {
      code: `if (!session_is_registered("username")) { echo "invalid session detected!"; exit; } update_profile();`,
      correct: false,
      explanation: 'Session validation alone cannot prevent CSRF since attackers forge requests through the user\'s browser within existing authenticated sessions, allowing email changes without user consent.'
    },
    {
      code: `if ($origin !== "https://trusted-site.com") { die("Invalid origin"); } update_email($newEmail);`,
      correct: false,
      explanation: 'Origin checking provides some protection but can be bypassed in older browsers or when the Origin header is not sent. Not as reliable as cryptographic CSRF tokens.'
    },
    {
      code: `if (!isset($_SERVER['HTTP_REFERER']) || strpos($_SERVER['HTTP_REFERER'], 'trusted-domain.com') === false) { die("Invalid referer"); }`,
      correct: false,
      explanation: 'Referer validation fails because privacy-conscious users and corporate proxies often strip referer headers, blocking legitimate requests while providing insufficient protection.'
    },
    {
      code: `if ($_POST['email_confirmation'] !== "yes_change_my_email") { die("Missing confirmation"); } update_email($_POST['newEmail']);`,
      correct: false,
      explanation: 'Simple confirmation strings can be included in malicious forms. MITRE attack example shows hidden form fields that auto-submit with any required values, including confirmations.'
    },
    {
      code: `if (!filter_var($_POST['newEmail'], FILTER_VALIDATE_EMAIL)) { die("Invalid email format"); } update_email($_POST['newEmail']);`,
      correct: false,
      explanation: 'Input validation is important but does not prevent CSRF. Attackers can provide properly formatted email addresses (like "attacker@evil.com") in their forged requests.'
    },
    {
      code: `$currentTime = time(); $requestTime = $_POST['timestamp']; if (abs($currentTime - $requestTime) > 300) { die("Request expired"); }`,
      correct: false,
      explanation: 'Timestamp validation does not prevent CSRF as malicious JavaScript can generate current timestamps dynamically when crafting the attack request.'
    },
    {
      code: `if ($_POST['userId'] != $_SESSION['userId']) { die("User ID mismatch"); } update_email($_POST['newEmail']);`,
      correct: false,
      explanation: 'User ID validation in POST data is meaningless since attackers can include the victim\'s user ID in their malicious forms after social engineering or reconnaissance.'
    },
    {
      code: `if (!isset($_SERVER['HTTP_X_REQUESTED_WITH']) || $_SERVER['HTTP_X_REQUESTED_WITH'] !== 'XMLHttpRequest') { die("Invalid request"); }`,
      correct: false,
      explanation: 'X-Requested-With header provides limited protection and can be bypassed. Modern CSRF attacks can include this header or use techniques that don\'t require it.'
    },
    {
      code: `sleep(2); // Rate limiting if (time() - $_SESSION['last_email_change'] < 60) { die("Too frequent"); } update_email($_POST['newEmail']);`,
      correct: false,
      explanation: 'Rate limiting helps reduce abuse but does not prevent CSRF. A successful attack only needs to work once, and the sleep delay affects legitimate users more than attackers.'
    }
  ]
}