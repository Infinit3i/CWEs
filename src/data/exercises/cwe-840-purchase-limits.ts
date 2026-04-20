import type { Exercise } from '@/data/exercises'

/**
 * CWE-840: Business Logic Errors - Purchase Limit Bypass
 * Business rule enforcement failure allowing limit circumvention
 */
export const cwe840PurchaseLimits: Exercise = {
  cweId: 'CWE-840',
  name: 'Business Logic Errors - Purchase Quantity Limits',

  vulnerableFunction: `function addToCart(productId, quantity, userId) {
  const product = getProduct(productId);
  const currentCart = getUserCart(userId);

  // Check individual item limit
  if (quantity > product.maxPerOrder) {
    throw new Error('Exceeds per-order limit');
  }

  // Add to cart
  currentCart.addItem(productId, quantity);
  return saveCart(currentCart);
}`,

  vulnerableLine: `if (quantity > product.maxPerOrder) {`,

  options: [
    {
      code: `const existingQty = currentCart.getItemQuantity(productId) || 0; if (existingQty + quantity > product.maxPerOrder) {`,
      correct: true,
      explanation: `Correct! This checks the total quantity including items already in cart. Prevents customers from bypassing limits by making multiple smaller orders that together exceed the business limit.`
    },
    {
      code: `if (quantity > product.maxPerOrder) { // Only check current addition`,
      correct: false,
      explanation: 'Classic business logic bypass from MITRE patterns. Customers can add items multiple times in smaller quantities to circumvent purchase limits, violating inventory management rules.'
    },
    {
      code: `if (quantity > product.maxPerOrder * 2) { // Double the limit`,
      correct: false,
      explanation: 'Arbitrary limit modification that ignores the business rule. Defeats the purpose of having purchase limits for inventory control or fair distribution policies.'
    },
    {
      code: `if (quantity > product.maxPerOrder && userId !== "admin") {`,
      correct: false,
      explanation: 'Creates inconsistent business logic where admins bypass limits. May violate regulatory compliance or fair distribution policies depending on the business context.'
    },
    {
      code: `const dailyPurchases = getDailyPurchases(userId, productId); if (quantity > product.maxPerOrder) {`,
      correct: false,
      explanation: 'Adds daily tracking but still has the core flaw. The immediate cart check ignores existing cart contents, allowing limit bypass through multiple additions.'
    },
    {
      code: `if (Math.abs(quantity) > product.maxPerOrder) {`,
      correct: false,
      explanation: 'Using absolute value suggests potential negative quantity handling but maintains the core bypass vulnerability. Multiple small additions still circumvent limits.'
    },
    {
      code: `if (quantity > product.maxPerOrder || quantity < 1) {`,
      correct: false,
      explanation: 'Adds minimum quantity check but preserves the business logic flaw. Multiple legitimate small orders can still exceed the intended maximum per customer.'
    },
    {
      code: `const roundedQty = Math.floor(quantity); if (roundedQty > product.maxPerOrder) {`,
      correct: false,
      explanation: 'Rounding addresses decimal quantities but ignores the core issue. Customers can still make multiple rounded additions to exceed limits.'
    },
    {
      code: `if (quantity > product.maxPerOrder && product.category === "limited") {`,
      correct: false,
      explanation: 'Category-based limiting but maintains the bypass vulnerability. For limited items, multiple small additions can still circumvent the business-critical purchase restrictions.'
    },
    {
      code: `const userLevel = getUserLevel(userId); if (quantity > product.maxPerOrder * userLevel.multiplier) {`,
      correct: false,
      explanation: 'User-level modifications but core logic remains flawed. Premium users might get higher limits, but they can still bypass through multiple additions regardless of their level.'
    }
  ]
}