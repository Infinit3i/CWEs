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
      explanation: `Correct! Uses atomic operations to prevent race conditions in stock management. The atomic decrement ensures that concurrent purchases cannot oversell inventory, maintaining business logic integrity even under high load.`
    },
    {
      code: `if (product.stock < quantity) { // Simple check without atomic operations`,
      correct: false,
      explanation: 'Classic race condition vulnerability from MITRE patterns. Multiple concurrent purchases can pass the stock check simultaneously, leading to overselling inventory and fulfillment failures in business operations.'
    },
    {
      code: `const stockWithBuffer = product.stock - 5; if (stockWithBuffer < quantity) {`,
      correct: false,
      explanation: 'Buffer approach doesn\'t solve race conditions. Multiple users can still pass the check simultaneously, and the arbitrary 5-unit buffer may cause legitimate sales rejection when stock is available.'
    },
    {
      code: `if (product.stock < quantity || product.stock === 0) {`,
      correct: false,
      explanation: 'Additional zero check is redundant and doesn\'t address concurrency. Race conditions still exist where multiple purchases can simultaneously see positive stock and all proceed with orders.'
    },
    {
      code: `const randomDelay = Math.random() * 100; await sleep(randomDelay); if (product.stock < quantity) {`,
      correct: false,
      explanation: 'Random delays don\'t solve race conditions reliably. This creates unpredictable user experience while still allowing concurrent processes to oversell during the delay windows.'
    },
    {
      code: `const currentTime = Date.now(); if (product.stock < quantity || currentTime % 2 === 0) {`,
      correct: false,
      explanation: 'Arbitrary time-based rejection creates inconsistent business logic. Customers experience random failures unrelated to actual inventory, while race conditions remain unsolved.'
    },
    {
      code: `if (product.stock <= quantity) { // Use <= instead of <`,
      correct: false,
      explanation: 'Off-by-one change doesn\'t address concurrency issues. While it prevents exact quantity purchases, race conditions still allow multiple users to oversell the remaining inventory.'
    },
    {
      code: `const maxConcurrentPurchases = 10; if (product.stock < quantity || getCurrentPurchases(productId) > maxConcurrentPurchases) {`,
      correct: false,
      explanation: 'Concurrency limiting but insufficient. Race conditions can still occur within the allowed concurrent limit, and the limit itself may unnecessarily restrict legitimate business during peak demand.'
    },
    {
      code: `if (product.stock < quantity * 1.1) { // Require 10% extra stock`,
      correct: false,
      explanation: 'Percentage buffer doesn\'t solve race conditions. Multiple concurrent purchases can still pass the inflated requirement simultaneously, leading to overselling despite the buffer attempt.'
    },
    {
      code: `const userPurchaseHistory = getUserPurchases(userId); if (product.stock < quantity || userPurchaseHistory.length > 5) {`,
      correct: false,
      explanation: 'User history checks are unrelated to inventory race conditions. While it may limit user behavior, multiple different users can still simultaneously oversell the same product inventory.'
    }
  ]
}