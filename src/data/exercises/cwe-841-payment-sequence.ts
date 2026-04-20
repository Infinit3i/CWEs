import type { Exercise } from '@/data/exercises'

/**
 * CWE-841: Improper Enforcement of Behavioral Workflow - Payment Processing Sequence
 * Payment workflow where verification steps can be bypassed
 */
export const cwe841PaymentSequence: Exercise = {
  cweId: 'CWE-841',
  name: 'Improper Enforcement of Behavioral Workflow - Payment Processing',

  vulnerableFunction: `function processPayment(transactionId, step, userId) {
  const transaction = getTransaction(transactionId);

  if (step === 'validate_card') {
    const isValid = validateCreditCard(transaction.cardNumber);
    if (isValid) {
      transaction.cardValidated = true;
      return 'Card validation successful';
    }
    return 'Card validation failed';
  }

  if (step === 'verify_funds') {
    const hasFunds = checkAvailableFunds(transaction.cardNumber, transaction.amount);
    if (hasFunds) {
      transaction.fundsVerified = true;
      return 'Funds verification successful';
    }
    return 'Insufficient funds';
  }

  if (step === 'charge_card') {
    const result = chargeCard(transaction.cardNumber, transaction.amount);
    transaction.status = 'completed';
    transaction.chargedDate = new Date();
    return result;
  }

  return 'Invalid step';
}`,

  vulnerableLine: `if (step === 'charge_card') {`,

  options: [
    {
      code: `if (step === 'charge_card' && transaction.cardValidated && transaction.fundsVerified) {`,
      correct: true,
      explanation: `Correct! Enforces the complete payment workflow sequence requiring both card validation and funds verification before charging. This prevents financial losses from incomplete validation sequences.`
    },
    {
      code: `if (step === 'charge_card') { // No workflow validation`,
      correct: false,
      explanation: 'Critical MITRE workflow bypass. Credit cards can be charged without validation or funds verification, potentially causing failed transactions, chargebacks, and compliance violations.'
    },
    {
      code: `if (step === 'charge_card' && transaction.cardValidated) {`,
      correct: false,
      explanation: 'Partial workflow enforcement. Cards can be charged after validation but without funds verification, leading to declined transactions and potential overdraft issues.'
    },
    {
      code: `if (step === 'charge_card' && transaction.amount < 100) {`,
      correct: false,
      explanation: 'Amount-based bypass violates workflow consistency. Small transactions skip validation entirely, creating security gaps and potential fraud vulnerabilities for micro-transactions.'
    },
    {
      code: `if (step === 'charge_card' && transaction.fundsVerified) {`,
      correct: false,
      explanation: 'Checks funds but not card validation. Invalid cards with sufficient funds can be charged, potentially causing payment processing errors and compliance violations.'
    },
    {
      code: `if (step === 'charge_card' && userId === transaction.userId) {`,
      correct: false,
      explanation: 'User ownership check but no payment workflow validation. Account owners can charge cards without any validation steps, completely bypassing payment security workflows.'
    },
    {
      code: `if (step === 'charge_card' && transaction.retryCount < 3) {`,
      correct: false,
      explanation: 'Retry-based approach ignores validation workflow. Cards can be charged repeatedly without validation or funds verification, potentially causing multiple failed transactions.'
    },
    {
      code: `if (step === 'charge_card') { if (!transaction.cardValidated) return 'Warning: unvalidated card'; chargeCard();`,
      correct: false,
      explanation: 'Warning without enforcement allows workflow bypass. Cards are charged despite validation warnings, creating payment processing risks and potential financial losses.'
    },
    {
      code: `if (step === 'charge_card' && (transaction.cardValidated || transaction.priority === 'urgent')) {`,
      correct: false,
      explanation: 'Priority bypass creates inconsistent workflow enforcement. Urgent transactions skip validation requirements, creating financial risk pathways and compliance gaps.'
    },
    {
      code: `if (step === 'charge_card' && Date.now() - transaction.createdDate < 300000) {`,
      correct: false,
      explanation: 'Time-based charging within 5 minutes bypasses validation workflow. Fresh transactions can be charged without any verification, creating immediate financial exposure.'
    }
  ]
}