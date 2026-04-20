import type { Exercise } from '@/data/exercises'

/**
 * CWE-840: Business Logic Errors - Price Manipulation in Order Processing
 * Business logic flaw where price calculation can be manipulated
 */
export const cwe840PriceManipulation: Exercise = {
  cweId: 'CWE-840',
  name: 'Business Logic Errors - Order Price Calculation',
  language: 'C#',

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
      explanation: `Get prices from database not client input`
    },
    {
      code: `const productPrice = item.price || 0; // Trust client price`,
      correct: false,
      explanation: 'Client sets prices enabling $0.01 purchases'
    },
    {
      code: `const productPrice = Math.max(item.price || 0, 1);`,
      correct: false,
      explanation: 'Minimum $1 but client still controls pricing'
    },
    {
      code: `const productPrice = parseFloat(item.price) || getDefaultPrice();`,
      correct: false,
      explanation: 'Parsing added but client price still trusted'
    },
    {
      code: `const productPrice = item.price ? Math.round(item.price * 100) / 100 : 0;`,
      correct: false,
      explanation: 'Rounds price but client controls amount'
    },
    {
      code: `const maxPrice = getProductMaxPrice(item.productId); const productPrice = Math.min(item.price || maxPrice, maxPrice);`,
      correct: false,
      explanation: 'Price capped high but client sets low amount'
    },
    {
      code: `const productPrice = item.discountedPrice || item.price || 0;`,
      correct: false,
      explanation: 'Multiple price fields all client-controlled'
    },
    {
      code: `const productPrice = item.price && item.price > 0 ? item.price : getBasePrice();`,
      correct: false,
      explanation: 'Positive check but small values bypass'
    },
    {
      code: `const categoryMultiplier = getCategoryMultiplier(item.category); const productPrice = (item.price || 0) * categoryMultiplier;`,
      correct: false,
      explanation: 'Category multiplier on client-controlled base price'
    },
    {
      code: `const productPrice = item.memberPrice && customerData.isMember ? item.memberPrice : item.price;`,
      correct: false,
      explanation: 'Member pricing but both prices client-controlled'
    }
  ]
}