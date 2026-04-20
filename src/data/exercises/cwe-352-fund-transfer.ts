import type { Exercise } from '@/data/exercises'

/**
 * CWE-352 exercise - Fund Transfer
 * Based on MITRE CSRF examples with financial transaction impacts
 */
export const cwe352FundTransfer: Exercise = {
  cweId: 'CWE-352',
  name: 'Cross-Site Request Forgery - Fund Transfer',

  vulnerableFunction: `app.post('/api/transfer', authenticateBanking, (req, res) => {
  const { toAccount, amount, description } = req.body;
  const fromAccount = req.user.accountNumber;

  // Verify sufficient balance
  if (!hasSufficientFunds(fromAccount, amount)) {
    return res.status(400).json({ error: 'Insufficient funds' });
  }

  processTransfer(fromAccount, toAccount, amount, description);
  res.json({ message: 'Transfer completed', transactionId: generateId() });
});`,

  vulnerableLine: `app.post('/api/transfer', authenticateBanking, (req, res) => {`,

  options: [
    {
      code: `const doubleSubmitCSRF = require('./csrf-middleware'); app.post('/api/transfer', authenticateBanking, doubleSubmitCSRF, (req, res) => { if (!req.csrfTokenValid) { return res.status(403).json({ error: 'Invalid CSRF token' }); }`,
      correct: true,
      explanation: `Correct! CSRF protection is critical for financial operations. The double-submit cookie pattern or synchronizer tokens prevent malicious sites from auto-submitting transfer forms, protecting users from unauthorized transactions even while logged into their banking session.`
    },
    {
      code: `<BODY onload="javascript:SendAttack();"> <form action="http://bank.example.com/api/transfer" method="post"> <input type="hidden" name="toAccount" value="attacker123"> <input type="hidden" name="amount" value="10000"> </form>`,
      correct: false,
      explanation: 'Direct from MITRE: This hidden form auto-submits when loaded, transferring funds to the attacker\'s account while the victim is logged into their banking session. No user interaction required.'
    },
    {
      code: `if (!req.session.authenticated) { return res.status(401).json({ error: 'Authentication required' }); } processTransfer(fromAccount, toAccount, amount);`,
      correct: false,
      explanation: 'MITRE pattern: Authentication alone cannot prevent CSRF since attackers exploit existing authenticated sessions through the user\'s browser, making unauthorized transfers appear legitimate.'
    },
    {
      code: `if (parseFloat(amount) > 1000) { return res.status(403).json({ error: 'Amount too large' }); } processTransfer(fromAccount, toAccount, amount);`,
      correct: false,
      explanation: 'Amount limits help reduce damage but do not prevent CSRF attacks. Attackers can make multiple smaller transfers or target the maximum allowed amount per transaction.'
    },
    {
      code: `const origin = req.headers.origin; if (!origin || origin !== 'https://secure-bank.com') { return res.status(403).json({ error: 'Invalid origin' }); } processTransfer(fromAccount, toAccount, amount);`,
      correct: false,
      explanation: 'Origin header checking provides some protection but can be bypassed and may not be present in all requests. Not as reliable as cryptographic CSRF tokens for financial operations.'
    },
    {
      code: `if (!req.body.pin || !verifyPIN(req.user.id, req.body.pin)) { return res.status(400).json({ error: 'Invalid PIN' }); } processTransfer(fromAccount, toAccount, amount);`,
      correct: false,
      explanation: 'PIN verification adds security but does not prevent CSRF if the attacker knows the PIN through social engineering, observation, or if the PIN is cached in the session.'
    },
    {
      code: `const userAgent = req.headers['user-agent']; if (!userAgent || userAgent.includes('curl') || userAgent.includes('wget')) { return res.status(403).json({ error: 'Invalid client' }); }`,
      correct: false,
      explanation: 'User-Agent filtering blocks obvious automated tools but does not prevent CSRF attacks from legitimate browsers, which will send proper user-agent strings with malicious requests.'
    },
    {
      code: `if (req.ip !== req.user.registeredIP) { return res.status(403).json({ error: 'IP address mismatch' }); } processTransfer(fromAccount, toAccount, amount);`,
      correct: false,
      explanation: 'IP validation breaks mobile banking and shared networks while not preventing CSRF, since the malicious request still originates from the victim\'s registered IP through their browser.'
    },
    {
      code: `if (!req.headers['x-requested-with']) { return res.status(403).json({ error: 'Missing required header' }); } processTransfer(fromAccount, toAccount, amount);`,
      correct: false,
      explanation: 'X-Requested-With header checking provides limited protection and can be bypassed by sophisticated attacks or may break legitimate requests from different client implementations.'
    },
    {
      code: `const timestamp = req.headers['x-timestamp']; if (!timestamp || Math.abs(Date.now() - timestamp) > 30000) { return res.status(403).json({ error: 'Request too old' }); }`,
      correct: false,
      explanation: 'Timestamp validation does not prevent CSRF as malicious JavaScript can generate fresh timestamps dynamically, and legitimate users may have clock skew issues blocking valid requests.'
    }
  ]
}