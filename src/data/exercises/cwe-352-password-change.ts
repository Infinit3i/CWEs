import type { Exercise } from '@/data/exercises'

/**
 * CWE-352 exercise - Password Change Form
 * Based on MITRE CSRF patterns with hidden form auto-submission
 */
export const cwe352PasswordChange: Exercise = {
  cweId: 'CWE-352',
  name: 'Cross-Site Request Forgery - Password Change',

  vulnerableFunction: `app.post('/change-password', isAuthenticated, (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const userId = req.session.userId;

  // Verify current password
  if (!verifyPassword(userId, currentPassword)) {
    return res.status(400).json({ error: 'Current password incorrect' });
  }

  updatePassword(userId, hashPassword(newPassword));
  res.json({ message: 'Password updated successfully' });
});`,

  vulnerableLine: `app.post('/change-password', isAuthenticated, (req, res) => {`,

  options: [
    {
      code: `app.post('/change-password', isAuthenticated, csrfProtection, (req, res) => { const token = req.body._csrf || req.headers['csrf-token']; if (!token || !validateCSRFToken(token, req.session.csrfSecret)) { return res.status(403).json({ error: 'CSRF token invalid' }); }`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    {
      code: `function SendAttack() { form.currentPassword = "user123"; form.newPassword = "attacker456"; form.submit(); }`,
      correct: false,
      explanation: 'This JavaScript automatically submits a hidden form when the page loads, changing the victim\'s password silently while they\'re logged in. No user interaction required for the attack to succeed.'
    },
    {
      code: `if (!isset($_SESSION['username'])) { echo "invalid session detected!"; exit; } change_password($_POST['newPassword']);`,
      correct: false,
      explanation: 'MITRE vulnerability: Session validation alone cannot prevent CSRF since attackers forge requests through the user\'s browser within existing authenticated sessions.'
    },
    {
      code: `if ($_SERVER['HTTP_REFERER'] !== "https://secure-app.com/change-password") { die("Invalid referer"); } update_password($_POST['newPassword']);`,
      correct: false,
      explanation: 'Referer validation is unreliable because many users have privacy settings or corporate proxies that strip referer headers, blocking legitimate requests while providing weak protection.'
    },
    {
      code: `if (time() - $_SESSION['login_time'] > 1800) { die("Session expired"); } change_password($_POST['newPassword']);`,
      correct: false,
      explanation: 'Session timeout validation is good practice but does not prevent CSRF attacks that occur within the valid session window, which is the typical attack scenario.'
    },
    {
      code: `if (!password_verify($_POST['currentPassword'], $user['password_hash'])) { die("Current password wrong"); } update_password($_POST['newPassword']);`,
      correct: false,
      explanation: 'Current password verification helps but does not prevent CSRF if the attacker knows the current password through social engineering, data breaches, or shoulder surfing.'
    },
    {
      code: `if ($_POST['confirmation'] !== "yes_change_password") { die("Missing confirmation"); } update_password($_POST['newPassword']);`,
      correct: false,
      explanation: 'Simple confirmation strings can be included in malicious hidden forms that auto-submit with all required fields, as shown in MITRE\'s attack examples.'
    },
    {
      code: `if (!preg_match('/^(?=.*[A-Z])(?=.*[a-z])(?=.*\\d)/', $_POST['newPassword'])) { die("Password too weak"); } update_password($_POST['newPassword']);`,
      correct: false,
      explanation: 'Password strength validation is important for security but does not prevent CSRF. Attackers can provide complex passwords that meet requirements while still compromising the account.'
    },
    {
      code: `if ($_SERVER['REQUEST_METHOD'] !== 'POST') { die("Invalid method"); } update_password($_POST['newPassword']);`,
      correct: false,
      explanation: 'HTTP method validation is standard practice but provides no CSRF protection, as malicious forms can easily submit POST requests with hidden fields.'
    },
    {
      code: `$userAgent = $_SERVER['HTTP_USER_AGENT']; if (empty($userAgent) || strpos($userAgent, 'bot') !== false) { die("Invalid user agent"); } update_password($_POST['newPassword']);`,
      correct: false,
      explanation: 'User-Agent validation is ineffective against CSRF because legitimate browsers will send proper user-agent strings when submitting malicious forms, allowing attacks to succeed.'
    }
  ]
}