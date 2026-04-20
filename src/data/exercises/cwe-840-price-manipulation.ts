import type { Exercise } from '@/data/exercises'

/**
 * CWE-840: Business Logic Errors - Price Manipulation in Order Processing
 * Business logic flaw where price calculation can be manipulated
 */
export const cwe840PriceManipulation: Exercise = {
  cweId: 'CWE-840',
  name: 'Business Logic Errors - Order Price Calculation',

  vulnerableFunction: `function processOrder(orderItems, customerData) {
  let totalPrice = 0;

  for (const item of orderItems) {
    const productPrice = item.price || 0;
    const quantity = item.quantity || 1;
    totalPrice += productPrice * quantity;
  }

  // Apply customer discount
  if (customerData.discountPercent) {
    totalPrice *= (1 - customerData.discountPercent / 100);
  }

  return submitPayment(totalPrice, customerData.paymentMethod);
}`,

  vulnerableLine: `const productPrice = item.price || 0;`,

  options: [
    {
      code: `const productPrice = getAuthorativePrice(item.productId);`,
      correct: true,
      explanation: `Correct! Retrieves price from authoritative database source rather than trusting client-provided prices. This prevents price manipulation attacks where users modify product prices in their requests to purchase items for less than intended.`
    },
    {
      code: `const productPrice = item.price || 0; // Trust client price`,
      correct: false,
      explanation: 'Critical business logic flaw from MITRE patterns. Trusting client-provided prices allows customers to set arbitrary prices, potentially purchasing expensive items for $0.01 or negative amounts.'
    },
    {
      code: `const productPrice = Math.max(item.price || 0, 1);`,
      correct: false,
      explanation: 'Prevents zero/negative prices but still trusts client input. Attackers can set prices to $1 for expensive items, causing massive financial losses while appearing to have minimal validation.'
    },
    {
      code: `const productPrice = parseFloat(item.price) || getDefaultPrice();`,
      correct: false,
      explanation: 'Parsing and fallback logic but core vulnerability remains. Client can still provide manipulated prices, and parseFloat can introduce precision issues that further complicate business logic.'
    },
    {
      code: `const productPrice = item.price ? Math.round(item.price * 100) / 100 : 0;`,
      correct: false,
      explanation: 'Currency rounding but trusts client price. Attackers can still set prices to rounded low values like $0.01, and the rounding doesn\'t address the fundamental trust boundary violation.'
    },
    {
      code: `const maxPrice = getProductMaxPrice(item.productId); const productPrice = Math.min(item.price || maxPrice, maxPrice);`,
      correct: false,
      explanation: 'Caps price at maximum but still allows manipulation downward. Customers can set any price below the maximum, potentially buying expensive items at fraction of intended cost.'
    },
    {
      code: `const productPrice = item.discountedPrice || item.price || 0;`,
      correct: false,
      explanation: 'Multiple price fields increase attack surface. Clients can manipulate either regular price or discounted price fields, giving them more vectors to exploit the business logic.'
    },
    {
      code: `const productPrice = item.price && item.price > 0 ? item.price : getBasePrice();`,
      correct: false,
      explanation: 'Positive price validation with fallback, but core issue persists. Attackers can provide small positive values to bypass validation while still achieving significant price manipulation.'
    },
    {
      code: `const categoryMultiplier = getCategoryMultiplier(item.category); const productPrice = (item.price || 0) * categoryMultiplier;`,
      correct: false,
      explanation: 'Category-based adjustment but maintains client price trust. Multipliers might increase manipulation impact, and attackers can still set base price to exploit business calculations.'
    },
    {
      code: `const productPrice = item.memberPrice && customerData.isMember ? item.memberPrice : item.price;`,
      correct: false,
      explanation: 'Member pricing logic but both prices come from client. Attackers can manipulate either regular or member prices, and the membership check doesn\'t validate price authenticity.'
    }
  ]
}