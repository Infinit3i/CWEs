import type { Exercise } from '@/data/exercises'

/**
 * CWE-362: Race Condition in Inventory Management System
 * Enterprise scenario: E-commerce inventory updates with concurrent order processing
 */
export const cwe362InventoryUpdate: Exercise = {
  cweId: 'CWE-362',
  name: 'Race Condition - Inventory Management',

  vulnerableFunction: `class InventoryService {
  async reserveProduct(productId: string, quantity: number, orderId: string) {
    // Check current inventory
    const product = await Product.findById(productId);
    const availableStock = product.stockQuantity;

    console.log(\`Checking inventory for product \${productId}: \${availableStock} available\`);

    if (availableStock < quantity) {
      throw new Error('Insufficient inventory');
    }

    // Reserve the inventory
    const newStock = availableStock - quantity;

    await Product.updateOne(
      { _id: productId },
      {
        stockQuantity: newStock,
        lastModified: new Date()
      }
    );

    // Create reservation record
    await Reservation.create({
      orderId,
      productId,
      quantity,
      reservedAt: new Date()
    });

    return {
      productId,
      reservedQuantity: quantity,
      remainingStock: newStock
    };
  }
}`,

  vulnerableLine: `const availableStock = product.stockQuantity;`,

  options: [
    {
      code: `const result = await Product.findByIdAndUpdate(productId, { $inc: { stockQuantity: -quantity } }, { returnDocument: 'after' }); if (result.stockQuantity < 0) { await Product.findByIdAndUpdate(productId, { $inc: { stockQuantity: quantity } }); throw new Error('Insufficient inventory'); }`,
      correct: true,
      explanation: `Correct! Atomic database operations with conditional rollback prevent inventory overselling. Using findByIdAndUpdate with $inc ensures the decrement operation is atomic, preventing race conditions between checking and updating stock.`
    },
    {
      code: `const availableStock = product.stockQuantity;`,
      correct: false,
      explanation: 'From MITRE: Race condition in e-commerce systems allows overselling when multiple orders check the same inventory level before any update occurs. This leads to negative inventory and unfulfillable orders.'
    },
    {
      code: `const availableStock = product.stockQuantity; if (quantity > 10) { await new Promise(resolve => setTimeout(resolve, 200)); }`,
      correct: false,
      explanation: 'Conditional delays based on order size do not prevent race conditions. The check-then-update sequence remains non-atomic, allowing concurrent orders to oversell inventory.'
    },
    {
      code: `await new Promise(resolve => setTimeout(resolve, Math.random() * 100)); const availableStock = product.stockQuantity;`,
      correct: false,
      explanation: 'Random delays before inventory checks worsen race conditions by creating unpredictable timing windows. This increases rather than decreases the likelihood of concurrent access issues.'
    },
    {
      code: `const availableStock = product.stockQuantity; const buffer = Math.max(1, Math.floor(availableStock * 0.1)); if (availableStock - buffer < quantity) throw new Error('Insufficient inventory');`,
      correct: false,
      explanation: 'Adding inventory buffers does not solve race conditions. Multiple concurrent requests can still read the same stock level and reserve beyond actual availability.'
    },
    {
      code: `const productRefresh = await Product.findById(productId); const availableStock = productRefresh.stockQuantity;`,
      correct: false,
      explanation: 'Re-fetching the product does not prevent race conditions. The fundamental issue of non-atomic check-then-update operations remains, allowing concurrent overselling.'
    },
    {
      code: `const availableStock = product.stockQuantity; console.log(\`Timestamp: \${Date.now()}, Stock: \${availableStock}, Order: \${orderId}\`);`,
      correct: false,
      explanation: 'Logging with timestamps does not address race conditions. The check-and-update sequence remains non-atomic, allowing multiple orders to succeed with insufficient inventory.'
    },
    {
      code: `const currentTime = Date.now(); const availableStock = product.stockQuantity; if (currentTime % 2 === 0) { await new Promise(resolve => setTimeout(resolve, 50)); }`,
      correct: false,
      explanation: 'Time-based conditional delays do not prevent race conditions. The inventory check-and-update operations remain non-atomic regardless of timing patterns.'
    }
  ]
}