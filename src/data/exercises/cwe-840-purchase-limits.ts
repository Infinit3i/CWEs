import type { Exercise } from '@/data/exercises'

/**
 * CWE-840: Business Logic Errors - Purchase Limit Bypass
 * Business rule enforcement failure allowing limit circumvention
 */
export const cwe840PurchaseLimits: Exercise = {
  cweId: 'CWE-840',
  name: 'Business Logic Errors - Purchase Quantity Limits',
  language: 'C#',

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
      explanation: `Check total cart quantity not just new items`
    },
    {
      code: `if (quantity > product.maxPerOrder) { // Only check current addition`,
      correct: false,
      explanation: 'Multiple small orders bypass quantity limits'
    },
    {
      code: `if (quantity > product.maxPerOrder * 2) { // Double the limit`,
      correct: false,
      explanation: 'Doubles limit breaking inventory control rules'
    },
    {
      code: `if (quantity > product.maxPerOrder && userId !== "admin") {`,
      correct: false,
      explanation: 'Admin bypass may violate fair distribution policies'
    },
    {
      code: `const dailyPurchases = getDailyPurchases(userId, productId); if (quantity > product.maxPerOrder) {`,
      correct: false,
      explanation: 'Daily tracking added but cart bypass remains'
    },
    {
      code: `if (Math.abs(quantity) > product.maxPerOrder) {`,
      correct: false,
      explanation: 'Handles negatives but multiple additions bypass limits'
    },
    {
      code: `if (quantity > product.maxPerOrder || quantity < 1) {`,
      correct: false,
      explanation: 'Minimum check added but small orders bypass limits'
    },
    {
      code: `const roundedQty = Math.floor(quantity); if (roundedQty > product.maxPerOrder) {`,
      correct: false,
      explanation: 'Rounds quantities but multiple adds bypass limits'
    },
    {
      code: `if (quantity > product.maxPerOrder && product.category === "limited") {`,
      correct: false,
      explanation: 'Limited items still bypassable through small adds'
    },
    {
      code: `const userLevel = getUserLevel(userId); if (quantity > product.maxPerOrder * userLevel.multiplier) {`,
      correct: false,
      explanation: 'User levels change limits but bypass remains'
    }
  ]
}