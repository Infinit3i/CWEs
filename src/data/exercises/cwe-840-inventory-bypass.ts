import type { Exercise } from '@/data/exercises'

/**
 * CWE-840: Business Logic Errors - Inventory Check Bypass
 * Race condition in inventory management business logic
 */
export const cwe840InventoryBypass: Exercise = {
  cweId: 'CWE-840',
  name: 'Business Logic Errors - Inventory Management',

  vulnerableFunction: `function purchaseProduct(productId, quantity, userId) {
  const product = getProduct(productId);

  // Check stock availability
  if (product.stock < quantity) {
    throw new Error('Insufficient stock');
  }

  // Process payment
  const payment = processPayment(userId, product.price * quantity);
  if (!payment.success) {
    throw new Error('Payment failed');
  }

  // Update inventory
  product.stock -= quantity;
  updateProduct(product);

  return createOrder(userId, productId, quantity);
}`,

  vulnerableLine: `if (product.stock < quantity) {`,

  options: [
    {
      code: `const updatedStock = atomicDecrementStock(productId, quantity); if (updatedStock < 0) { atomicIncrementStock(productId, quantity); throw new Error('Insufficient stock'); }`,
      correct: true,
      explanation: `Use atomic operations to prevent overselling`
    },
    {
      code: `if (product.stock < quantity) { // Simple check without atomic operations`,
      correct: false,
      explanation: 'Race condition allows multiple orders to oversell'
    },
    {
      code: `const stockWithBuffer = product.stock - 5; if (stockWithBuffer < quantity) {`,
      correct: false,
      explanation: 'Buffer reduces stock but race condition remains'
    },
    {
      code: `if (product.stock < quantity || product.stock === 0) {`,
      correct: false,
      explanation: 'Extra zero check but concurrent overselling possible'
    },
    {
      code: `const randomDelay = Math.random() * 100; await sleep(randomDelay); if (product.stock < quantity) {`,
      correct: false,
      explanation: 'Random delays create poor UX and overselling'
    },
    {
      code: `const currentTime = Date.now(); if (product.stock < quantity || currentTime % 2 === 0) {`,
      correct: false,
      explanation: 'Random time-based rejection breaks business logic'
    },
    {
      code: `if (product.stock <= quantity) { // Use <= instead of <`,
      correct: false,
      explanation: 'Off-by-one fix but race condition remains'
    },
    {
      code: `const maxConcurrentPurchases = 10; if (product.stock < quantity || getCurrentPurchases(productId) > maxConcurrentPurchases) {`,
      correct: false,
      explanation: 'Limits concurrent purchases but overselling still possible'
    },
    {
      code: `if (product.stock < quantity * 1.1) { // Require 10% extra stock`,
      correct: false,
      explanation: 'Percentage buffer but concurrent overselling remains'
    },
    {
      code: `const userPurchaseHistory = getUserPurchases(userId); if (product.stock < quantity || userPurchaseHistory.length > 5) {`,
      correct: false,
      explanation: 'User limits but multiple users oversell inventory'
    }
  ]
}