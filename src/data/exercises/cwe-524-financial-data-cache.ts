import type { Exercise } from '@/data/exercises'

/**
 * CWE-524 Exercise 5: Financial Data Caching
 * Based on caching sensitive financial and payment information
 */
export const cwe524FinancialDataCache: Exercise = {
  cweId: 'CWE-524',
  name: 'Financial Data Cache - Payment Processing Cache',
  language: 'JavaScript',

  vulnerableFunction: `function processPayment(paymentData, userId) {
  const cacheKey = \`payment:\${userId}:\${paymentData.transactionId}\`;

  // Check cache for duplicate transaction
  if (paymentCache[cacheKey]) {
    return paymentCache[cacheKey];
  }

  // Process payment with external service
  const paymentResult = paymentGateway.processPayment({
    amount: paymentData.amount,
    currency: paymentData.currency,
    cardNumber: paymentData.cardNumber,
    expiryDate: paymentData.expiryDate,
    cvv: paymentData.cvv,
    billingAddress: paymentData.billingAddress
  });

  // Cache complete payment information for audit and debugging
  paymentCache[cacheKey] = {
    transactionId: paymentData.transactionId,
    userId: userId,
    amount: paymentData.amount,
    currency: paymentData.currency,
    cardNumber: paymentData.cardNumber,
    expiryDate: paymentData.expiryDate,
    cvv: paymentData.cvv,
    billingAddress: paymentData.billingAddress,
    gatewayResponse: paymentResult,
    processedAt: Date.now(),
    status: paymentResult.success ? 'completed' : 'failed'
  };

  return paymentCache[cacheKey];
}`,

  vulnerableLine: `cardNumber: paymentData.cardNumber,`,

  options: [
    {
      code: `// Cache only non-sensitive payment metadata
paymentCache[cacheKey] = {
  transactionId: paymentData.transactionId,
  userId: userId,
  amount: paymentData.amount,
  currency: paymentData.currency,
  status: paymentResult.success ? 'completed' : 'failed',
  processedAt: Date.now(),
  lastFourDigits: paymentData.cardNumber.slice(-4)
  // Never cache full card numbers, CVV, or expiry dates
};`,
      correct: true,
      explanation: `Clear cache after sensitive operations`
    },
    {
      code: `paymentCache[cacheKey] = {
  cardNumber: paymentData.cardNumber,
  expiryDate: paymentData.expiryDate,
  cvv: paymentData.cvv,
  amount: paymentData.amount
};`,
      correct: false,
      explanation: 'Caching complete payment card data enables financial fraud and identity theft. Attackers who access cache can extract credit card numbers, CVV codes, and expiry dates.'
    },
    {
      code: `const maskedCard = paymentData.cardNumber.replace(/\\d(?=\\d{4})/g, '*');
paymentCache[cacheKey] = {
  ...paymentData,
  cardNumber: maskedCard,
  amount: paymentData.amount
};`,
      correct: false,
      explanation: 'Partial masking of card numbers still leaves CVV and expiry date exposed. Complete exclusion of sensitive payment data is safer.'
    },
    {
      code: `paymentCache[cacheKey] = {
  publicInfo: {
    transactionId: paymentData.transactionId,
    amount: paymentData.amount
  },
  sensitiveInfo: {
    cardNumber: paymentData.cardNumber,
    cvv: paymentData.cvv
  }
};`,
      correct: false,
      explanation: 'Organizing sensitive data in separate objects does not prevent exposure. The payment card data is still stored in cache memory.'
    },
    {
      code: `const encryptedCard = encrypt(paymentData.cardNumber);
const encryptedCvv = encrypt(paymentData.cvv);
paymentCache[cacheKey] = {
  ...paymentData,
  cardNumber: encryptedCard,
  cvv: encryptedCvv
};`,
      correct: false,
      explanation: 'Encryption in cache increases complexity and risk. Payment card data should not be cached regardless of encryption due to PCI compliance requirements.'
    },
    {
      code: `if (paymentData.cardNumber.startsWith('4111')) { // Test card
  paymentCache[cacheKey] = { ...paymentData };
} else {
  paymentCache[cacheKey] = {
    transactionId: paymentData.transactionId,
    amount: paymentData.amount
  };
}`,
      correct: false,
      explanation: 'Test card detection is incomplete and unreliable. Real card data could still be cached if detection fails.'
    },
    {
      code: `try {
  paymentCache[cacheKey] = Object.freeze({
    cardNumber: paymentData.cardNumber,
    cvv: paymentData.cvv,
    amount: paymentData.amount,
    immutable: true
  });
} catch {}`,
      correct: false,
      explanation: 'Freezing objects does not prevent sensitive data exposure. Payment card information is still accessible in cache memory.'
    },
    {
      code: `const hashedCard = hash(paymentData.cardNumber);
const hashedCvv = hash(paymentData.cvv);
paymentCache[cacheKey] = {
  cardHash: hashedCard,
  cvvHash: hashedCvv,
  amount: paymentData.amount
};`,
      correct: false,
      explanation: 'Hashing payment data is unnecessary and potentially harmful. Card hashes could still be valuable for fingerprinting and attack correlation.'
    },
    {
      code: `setTimeout(() => delete paymentCache[cacheKey], 60000); // 1 minute
paymentCache[cacheKey] = {
  cardNumber: paymentData.cardNumber,
  cvv: paymentData.cvv,
  temporary: true
};`,
      correct: false,
      explanation: 'Temporary caching with expiration does not prevent exposure during the cache lifetime. Payment data is still accessible to attackers.'
    },
    {
      code: `const paymentInfo = { ...paymentData };
if (paymentInfo.cardNumber.length > 16) {
  delete paymentInfo.cardNumber;
}
paymentCache[cacheKey] = paymentInfo;`,
      correct: false,
      explanation: 'Length-based exclusion is unreliable and incomplete. Standard card numbers (16 digits) would still be cached, and CVV/expiry remain exposed.'
    }
  ]
}