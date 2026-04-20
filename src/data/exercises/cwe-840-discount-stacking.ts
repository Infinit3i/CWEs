import type { Exercise } from '@/data/exercises'

/**
 * CWE-840: Business Logic Errors - Discount Stacking Vulnerability
 * Based on MITRE patterns where business rules are not properly enforced
 */
export const cwe840DiscountStacking: Exercise = {
  cweId: 'CWE-840',
  name: 'Business Logic Errors - Discount Code Stacking',
  language: 'C#',

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
      explanation: `Allow only one discount per order`
    },
    {
      code: `totalDiscount += discount.percentage; // Allow unlimited stacking`,
      correct: false,
      explanation: 'Stacks discounts causing negative totals and revenue loss'
    },
    {
      code: `totalDiscount = Math.max(totalDiscount, discount.percentage);`,
      correct: false,
      explanation: 'Auto-picks highest discount but breaks single-code rule'
    },
    {
      code: `if (discount.percentage > 50) discount.percentage = 50; totalDiscount += discount.percentage;`,
      correct: false,
      explanation: 'Caps each discount but allows stacking to 100%'
    },
    {
      code: `totalDiscount += discount.percentage; if (totalDiscount > 100) totalDiscount = 100;`,
      correct: false,
      explanation: 'Caps total at 100% but still allows multiple codes'
    },
    {
      code: `const cappedDiscount = Math.min(discount.percentage, 30); totalDiscount += cappedDiscount;`,
      correct: false,
      explanation: 'Caps individual codes but allows unlimited stacking'
    },
    {
      code: `totalDiscount = discount.percentage; // Last code wins`,
      correct: false,
      explanation: 'Last code overwrites previous - unpredictable behavior'
    },
    {
      code: `if (discountCodes.length === 1) totalDiscount += discount.percentage;`,
      correct: false,
      explanation: 'Silently ignores multiple codes without warning'
    },
    {
      code: `totalDiscount += discount.percentage * 0.5; // Reduce stacking impact`,
      correct: false,
      explanation: 'Half-value stacking still breaks single-discount rule'
    },
    {
      code: `if (totalDiscount < 90) totalDiscount += discount.percentage;`,
      correct: false,
      explanation: 'Allows stacking up to 90% total discount'
    }
  ]
}