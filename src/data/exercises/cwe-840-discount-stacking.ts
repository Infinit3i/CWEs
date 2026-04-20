import type { Exercise } from '@/data/exercises'

/**
 * CWE-840: Business Logic Errors - Discount Stacking Vulnerability
 * Based on MITRE patterns where business rules are not properly enforced
 */
export const cwe840DiscountStacking: Exercise = {
  cweId: 'CWE-840',
  name: 'Business Logic Errors - Discount Code Stacking',

  vulnerableFunction: `function applyDiscounts(cart, discountCodes) {
  let totalDiscount = 0;

  for (const code of discountCodes) {
    const discount = validateDiscountCode(code);
    if (discount && discount.isValid) {
      totalDiscount += discount.percentage;
      logDiscountUsage(code, discount.percentage);
    }
  }

  return cart.total * (1 - totalDiscount / 100);
}`,

  vulnerableLine: `totalDiscount += discount.percentage;`,

  options: [
    {
      code: `if (totalDiscount === 0) { totalDiscount = discount.percentage; } else { return cart.total; }`,
      correct: true,
      explanation: `Correct! This enforces the business rule of allowing only one discount per transaction. By checking if totalDiscount is already non-zero, we prevent discount stacking and maintain the intended single-discount business logic.`
    },
    {
      code: `totalDiscount += discount.percentage; // Allow unlimited stacking`,
      correct: false,
      explanation: 'Classic business logic flaw from MITRE patterns. Allows customers to stack multiple discount codes, potentially reducing order total to negative values and causing financial losses.'
    },
    {
      code: `totalDiscount = Math.max(totalDiscount, discount.percentage);`,
      correct: false,
      explanation: 'While this prevents negative totals, it violates business rules by allowing customers to apply multiple codes and automatically selecting the best one, which may not be the intended behavior.'
    },
    {
      code: `if (discount.percentage > 50) discount.percentage = 50; totalDiscount += discount.percentage;`,
      correct: false,
      explanation: 'Caps individual discounts but still allows stacking. Multiple 50% discounts can be combined, enabling 100%+ discounts and potential revenue loss.'
    },
    {
      code: `totalDiscount += discount.percentage; if (totalDiscount > 100) totalDiscount = 100;`,
      correct: false,
      explanation: 'Limits total discount to 100% but still allows stacking logic. Business rule violation where multiple codes should not be combinable regardless of the final percentage.'
    },
    {
      code: `const cappedDiscount = Math.min(discount.percentage, 30); totalDiscount += cappedDiscount;`,
      correct: false,
      explanation: 'Reduces individual discount impact but maintains the core stacking vulnerability. Multiple 30% discounts can still be combined beyond business intent.'
    },
    {
      code: `totalDiscount = discount.percentage; // Last code wins`,
      correct: false,
      explanation: 'Prevents stacking by overwriting but creates unpredictable behavior. Users can apply multiple codes with the last one taking effect, potentially gaming the system.'
    },
    {
      code: `if (discountCodes.length === 1) totalDiscount += discount.percentage;`,
      correct: false,
      explanation: 'Prevents stacking but fails silently when multiple codes are provided. Poor user experience and potential business logic confusion about which codes are valid.'
    },
    {
      code: `totalDiscount += discount.percentage * 0.5; // Reduce stacking impact`,
      correct: false,
      explanation: 'Arbitrary reduction of stacking impact but still allows the fundamental business logic violation. Half-value stacking is still stacking and violates single-discount rules.'
    },
    {
      code: `if (totalDiscount < 90) totalDiscount += discount.percentage;`,
      correct: false,
      explanation: 'Prevents excessive stacking but still allows multiple codes to be combined up to 90%. Violates the core business rule of single discount per transaction.'
    }
  ]
}