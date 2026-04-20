import type { Exercise } from '@/data/exercises'

/**
 * CWE-190 exercise: Financial calculation overflow
 * Based on revenue calculation vulnerabilities in business systems
 */
export const cwe190FinancialCalculation: Exercise = {
  cweId: 'CWE-190',
  name: 'Integer Overflow - Revenue Calculation System',

  vulnerableFunction: `function calculateMonthlyRevenue(salesData) {
  let totalRevenue = 0; // Using 32-bit signed integer (max ~2.1 billion)

  for (const sale of salesData) {
    const saleAmount = sale.price * sale.quantity;
    totalRevenue += saleAmount;

    // Apply bulk discount for large orders
    if (sale.quantity > 1000) {
      const discount = saleAmount * 0.05;
      totalRevenue -= Math.floor(discount);
    }
  }

  // Add monthly bonus
  const monthlyBonus = totalRevenue * 0.1;
  totalRevenue += Math.floor(monthlyBonus);

  return {
    revenue: totalRevenue,
    formatted: \`$\${totalRevenue.toLocaleString()}\`
  };
}`,

  vulnerableLine: `totalRevenue += saleAmount;`,

  options: [
    {
      code: `function calculateMonthlyRevenue(salesData) {
  let totalRevenue = 0;
  const MAX_REVENUE = Number.MAX_SAFE_INTEGER;

  for (const sale of salesData) {
    const saleAmount = sale.price * sale.quantity;

    if (totalRevenue > MAX_REVENUE - saleAmount) {
      throw new Error('Revenue calculation would overflow');
    }

    totalRevenue += saleAmount;
  }

  return { revenue: totalRevenue };
}`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    // Financial calculation overflow vulnerabilities
    {
      code: `let totalRevenue = 0;
for (const sale of salesData) {
    const saleAmount = sale.price * sale.quantity;
    totalRevenue += saleAmount; // Can overflow with large sales
}`,
      correct: false,
      explanation: 'MITRE-style revenue accumulation without overflow checking. With enough large sales, totalRevenue can wrap to negative values, showing massive losses instead of profits.'
    },
    {
      code: `let monthlyTotal = 0;
for (let month = 1; month <= 12; month++) {
    monthlyTotal += getSalesForMonth(month) * averagePrice;
}`,
      correct: false,
      explanation: 'Multiplication followed by addition creates multiple overflow points. Both the monthly calculation and yearly accumulation can overflow independently.'
    },
    {
      code: `const yearlyRevenue = quarterlyRevenue * 4;
const projectedGrowth = yearlyRevenue * growthRate;
return yearlyRevenue + projectedGrowth;`,
      correct: false,
      explanation: 'Chained arithmetic operations amplify overflow risk. Each multiplication can cause wraparound, leading to completely incorrect financial projections.'
    },
    {
      code: `if (totalRevenue > 0) {
    totalRevenue += saleAmount;
} else {
    totalRevenue = saleAmount; // Reset if negative
}`,
      correct: false,
      explanation: 'Checking positivity after overflow has occurred. Large positive sales can wrap to negative values, triggering incorrect resets.'
    },
    {
      code: `const clampedRevenue = Math.min(totalRevenue + saleAmount, 2147483647);
totalRevenue = clampedRevenue;`,
      correct: false,
      explanation: 'Clamping after addition is too late. The addition may have already overflowed before the Math.min constraint is applied.'
    },
    {
      code: `totalRevenue = (totalRevenue + saleAmount) & 0x7FFFFFFF;`,
      correct: false,
      explanation: 'Bit masking to force positive values corrupts financial data. Legitimate large revenues get truncated, causing incorrect business reporting.'
    },
    {
      code: `const safeRevenue = parseInt((totalRevenue + saleAmount).toString().substring(0, 9));
totalRevenue = safeRevenue;`,
      correct: false,
      explanation: 'String truncation creates arbitrary financial data. Revenue calculations become meaningless when digits are arbitrarily removed.'
    },
    {
      code: `if (saleAmount < 1000000) { // Only process small sales
    totalRevenue += saleAmount;
}`,
      correct: false,
      explanation: 'Arbitrary input limits may exclude legitimate large sales. Business logic should handle all valid transactions, not skip high-value ones.'
    },
    {
      code: `try {
    totalRevenue += saleAmount;
    if (totalRevenue.toString().includes('e+')) { // Scientific notation check
        throw new Error('Overflow detected');
    }
} catch (e) {
    totalRevenue = 0; // Reset on overflow
}`,
      correct: false,
      explanation: 'JavaScript integer overflow does not produce scientific notation or throw exceptions. This check will never detect overflow conditions.'
    }
  ]
}