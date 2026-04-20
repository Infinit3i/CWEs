import type { Exercise } from '@/data/exercises'

export const cwe20PurchaseQuantity: Exercise = {
  cweId: 'CWE-20',
  name: 'Improper Input Validation - Purchase Transaction',

  vulnerableFunction: `function processPurchase(userId, itemId) {
  const ITEM_PRICE = 20.00;

  // Get quantity from user session
  const quantity = getUserAttribute(userId, 'quantity');

  // Calculate total cost
  const totalCost = ITEM_PRICE * quantity;

  // Process payment
  const result = chargeUserAccount(userId, totalCost);

  return {
    itemId,
    quantity,
    unitPrice: ITEM_PRICE,
    total: totalCost,
    charged: result.success
  };
}`,

  vulnerableLine: `const totalCost = ITEM_PRICE * quantity;`,

  options: [
    {
      code: `if (quantity > 0 && Number.isInteger(quantity)) { const totalCost = ITEM_PRICE * quantity; } else { throw new Error('Invalid quantity'); }`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    {
      code: `const totalCost = ITEM_PRICE * quantity;`,
      correct: false,
      explanation: 'MITRE negative quantity pattern: No validation on quantity value. Attacker can specify negative quantity (-5) causing negative total cost, resulting in account credit instead of charge, effectively stealing money from the system.'
    },
    {
      code: `if (quantity !== 0) { const totalCost = ITEM_PRICE * quantity; }`,
      correct: false,
      explanation: 'Zero check insufficient - allows negative values. Attacker can still use negative quantities to generate credits and exploit the payment system for financial gain.'
    },
    {
      code: `const totalCost = ITEM_PRICE * Math.abs(quantity);`,
      correct: false,
      explanation: 'Math.abs() converts negative to positive but loses business intent. User who specified -5 items should receive validation error, not automatic conversion to 5 items purchased.'
    },
    {
      code: `if (quantity < 1000) { const totalCost = ITEM_PRICE * quantity; }`,
      correct: false,
      explanation: 'Upper bound check misses negative values. Quantities like -50 pass this validation but still create negative charges, allowing financial exploitation.'
    },
    {
      code: `const quantity = Math.max(1, getUserAttribute(userId, 'quantity')); const totalCost = ITEM_PRICE * quantity;`,
      correct: false,
      explanation: 'Forcing minimum of 1 silently changes user intent. Someone who enters invalid quantity should receive error feedback, not automatic adjustment to valid purchase.'
    },
    {
      code: `if (typeof quantity === 'number') { const totalCost = ITEM_PRICE * quantity; }`,
      correct: false,
      explanation: 'Type checking allows negative numbers. Negative values are still valid numbers but create invalid business logic allowing financial exploitation through negative charges.'
    },
    {
      code: `if (quantity) { const totalCost = ITEM_PRICE * quantity; }`,
      correct: false,
      explanation: 'Truthy check allows negative values. Negative numbers are truthy in JavaScript, so this validation fails to prevent the financial exploitation vulnerability.'
    },
    {
      code: `try { const totalCost = ITEM_PRICE * quantity; chargeUserAccount(userId, totalCost); } catch(e) { /* handle error */ }`,
      correct: false,
      explanation: 'Exception handling after calculation is too late. The negative total has already been computed and may be processed before any error handling occurs.'
    },
    {
      code: `if (!isNaN(quantity)) { const totalCost = ITEM_PRICE * quantity; }`,
      correct: false,
      explanation: 'NaN check does not validate range. Negative numbers are valid numbers (not NaN) but create business logic vulnerabilities in financial calculations.'
    }
  ]
}