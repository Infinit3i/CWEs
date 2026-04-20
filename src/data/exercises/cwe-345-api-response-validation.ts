import type { Exercise } from '@/data/exercises'

/**
 * CWE-345: Insufficient Verification of Data Authenticity - API Response Validation
 * Trusting API responses without proper authentication verification
 */
export const cwe345ApiResponseValidation: Exercise = {
  cweId: 'CWE-345',
  name: 'Insufficient Verification of Data Authenticity - API Integration',

  vulnerableFunction: `async function processPaymentConfirmation(transactionId) {
  try {
    // Query payment gateway for transaction status
    const response = await fetch(\`https://payments.api.com/transactions/\${transactionId}\`);
    const paymentData = await response.json();

    // Verify payment was successful
    if (paymentData.status === 'completed' && paymentData.amount > 0) {
      // Update order status
      await updateOrderStatus(paymentData.orderId, 'paid');

      // Grant access to purchased content
      await enableUserAccess(paymentData.userId, paymentData.productId);

      // Send confirmation email
      await sendConfirmationEmail(paymentData.userEmail, paymentData.orderId);

      return {
        success: true,
        message: 'Payment confirmed and access granted'
      };
    }

    return {
      success: false,
      message: 'Payment not completed'
    };

  } catch (error) {
    return {
      success: false,
      error: error.message
    };
  }
}`,

  vulnerableLine: `if (paymentData.status === 'completed' && paymentData.amount > 0) {`,

  options: [
    {
      code: `if (!verifyHMAC(paymentData, response.headers['x-signature'], webhookSecret)) { throw new Error('Invalid payment signature'); } if (paymentData.status === 'completed' && paymentData.amount > 0) {`,
      correct: true,
      explanation: `Correct! Verifies HMAC signature using shared webhook secret before trusting payment data. This prevents attackers from forging payment confirmations by validating the data came from the legitimate payment gateway.`
    },
    {
      code: `if (paymentData.status === 'completed' && paymentData.amount > 0) { // Trust API response`,
      correct: false,
      explanation: 'MITRE authenticity vulnerability. Trusting API responses without verification allows attackers to intercept/modify responses or create fake payment confirmations, granting unauthorized access to paid content.'
    },
    {
      code: `if (response.status === 200 && paymentData.status === 'completed' && paymentData.amount > 0) {`,
      correct: false,
      explanation: 'HTTP status checking doesn\'t verify response authenticity. Attackers can return HTTP 200 with fake payment data through man-in-the-middle attacks or API spoofing.'
    },
    {
      code: `const responseHash = calculateSHA256(JSON.stringify(paymentData)); if (responseHash && paymentData.status === 'completed') {`,
      correct: false,
      explanation: 'Self-calculated hash provides no authenticity verification. Attackers can create any fake payment data and calculate its hash, as there\'s no trusted source to compare against.'
    },
    {
      code: `if (paymentData.timestamp && Date.now() - paymentData.timestamp < 300000 && paymentData.status === 'completed') {`,
      correct: false,
      explanation: 'Timestamp validation helps prevent replay attacks but doesn\'t verify response authenticity. Fresh fake payment data can still be crafted within the time window.'
    },
    {
      code: `if (paymentData.gateway === 'trusted_gateway' && paymentData.status === 'completed' && paymentData.amount > 0) {`,
      correct: false,
      explanation: 'Gateway field checking doesn\'t prevent spoofing. Attackers can include gateway="trusted_gateway" in fake responses since this field isn\'t cryptographically verified.'
    },
    {
      code: `const expectedUrl = \`https://payments.api.com/transactions/\${transactionId}\`; if (response.url === expectedUrl && paymentData.status === 'completed') {`,
      correct: false,
      explanation: 'URL validation doesn\'t guarantee response authenticity. Attackers can intercept legitimate requests and provide fake responses that appear to come from the correct URL.'
    },
    {
      code: `if (paymentData.orderId && paymentData.userId && paymentData.status === 'completed' && paymentData.amount > 0) {`,
      correct: false,
      explanation: 'Field presence validation doesn\'t verify authenticity. Attackers can easily include all required fields in fake payment confirmations without cryptographic verification.'
    },
    {
      code: `const parsedAmount = parseFloat(paymentData.amount); if (parsedAmount > 0 && paymentData.status === 'completed') {`,
      correct: false,
      explanation: 'Amount parsing doesn\'t address authenticity issues. Attackers can provide properly formatted fake payment data with valid amounts that bypass parsing checks.'
    },
    {
      code: `if (paymentData.version === '1.0' && paymentData.status === 'completed' && paymentData.amount >= 0.01) {`,
      correct: false,
      explanation: 'Version and minimum amount checking don\'t prevent fake responses. Attackers can craft version-compliant fake payment confirmations with appropriate amounts to bypass these validations.'
    }
  ]
}