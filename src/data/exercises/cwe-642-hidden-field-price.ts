import type { Exercise } from '@/data/exercises'

/**
 * CWE-642: External Control of Critical State Data - Hidden Form Field Price Manipulation
 * Based on MITRE shopping cart example where prices are stored in client-controlled fields
 */
export const cwe642HiddenFieldPrice: Exercise = {
  cweId: 'CWE-642',
  name: 'External Control of Critical State Data - Shopping Cart Price',
  language: 'PHP',

  vulnerableFunction: `function processCheckout(formData) {
  const items = [];
  let totalPrice = 0;

  for (let i = 0; i < formData.itemCount; i++) {
    const item = {
      productId: formData[\`product_\${i}\`],
      quantity: parseInt(formData[\`quantity_\${i}\`]),
      price: parseFloat(formData[\`price_\${i}\`])
    };

    items.push(item);
    totalPrice += item.quantity * item.price;
  }

  const tax = totalPrice * 0.08;
  const finalTotal = totalPrice + tax;

  return {
    items: items,
    subtotal: totalPrice,
    tax: tax,
    total: finalTotal
  };
}`,

  vulnerableLine: `price: parseFloat(formData[\`price_\${i}\`])`,

  options: [
    {
      code: `price: getAuthorativeProductPrice(formData[\`product_\${i}\`])`,
      correct: true,
      explanation: `Get price from database not hidden fields`
    },
    {
      code: `price: parseFloat(formData[\`price_\${i}\`]) // Trust client price`,
      correct: false,
      explanation: 'Direct MITRE vulnerability pattern. Trusting client-provided prices in hidden fields allows customers to set arbitrary prices, potentially purchasing expensive items for pennies.'
    },
    {
      code: `price: Math.abs(parseFloat(formData[\`price_\${i}\`]))`,
      correct: false,
      explanation: 'Absolute value prevents negative prices but still trusts client data. Customers can set prices to $0.01 for expensive items, causing significant revenue loss.'
    },
    {
      code: `price: Math.max(1, parseFloat(formData[\`price_\${i}\`]))`,
      correct: false,
      explanation: 'Minimum price validation but core vulnerability remains. Customers can set prices to $1 for any item regardless of actual value, causing massive financial losses.'
    },
    {
      code: `const submittedPrice = parseFloat(formData[\`price_\${i}\`]); price: submittedPrice > 0 ? submittedPrice : 99.99`,
      correct: false,
      explanation: 'Positive price check with fallback but still vulnerable. Customers can submit any positive value like $0.01, and the fallback only applies to zero/negative values.'
    },
    {
      code: `price: parseFloat(formData[\`price_\${i}\`].replace(/[^0-9.]/g, ''))`,
      correct: false,
      explanation: 'Input sanitization doesn\'t address the trust issue. Customers can still submit sanitized low prices like "0.01" to purchase items far below market value.'
    },
    {
      code: `const maxPrice = 10000; price: Math.min(parseFloat(formData[\`price_\${i}\`]), maxPrice)`,
      correct: false,
      explanation: 'Maximum price cap but no minimum validation against actual price. Customers can set any price below $10,000, including $0.01 for expensive items.'
    },
    {
      code: `price: parseFloat(formData[\`discounted_price_\${i}\`] || formData[\`price_\${i}\`])`,
      correct: false,
      explanation: 'Multiple client-controlled price fields increase attack surface. Customers can manipulate either regular or discounted price fields to achieve unauthorized pricing.'
    },
    {
      code: `const encryptedPrice = formData[\`price_\${i}\`]; price: parseFloat(decrypt(encryptedPrice))`,
      correct: false,
      explanation: 'Client-side encryption doesn\'t solve the trust issue if clients control the encrypted value. Customers can encrypt arbitrary prices or manipulate the encrypted data.'
    },
    {
      code: `const priceStr = formData[\`price_\${i}\`]; price: priceStr.length > 3 ? parseFloat(priceStr) : 0`,
      correct: false,
      explanation: 'Length-based validation is arbitrary and bypassable. Customers can submit "0.01" (4 characters) to pass validation while achieving significant price manipulation.'
    }
  ]
}