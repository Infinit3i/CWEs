import type { Exercise } from '@/data/exercises'

/**
 * CWE-841: Improper Enforcement of Behavioral Workflow - Order Processing Steps
 * Based on MITRE pattern where required sequence steps can be bypassed
 */
export const cwe841WorkflowBypass: Exercise = {
  cweId: 'CWE-841',
  name: 'Improper Enforcement of Behavioral Workflow - Order Processing',

  vulnerableFunction: `function processOrderStep(orderId, stepType, userId) {
  const order = getOrder(orderId);

  if (stepType === 'approve') {
    if (userId !== order.managerId) {
      throw new Error('Unauthorized approval');
    }
    order.status = 'approved';
  }

  if (stepType === 'ship') {
    order.status = 'shipped';
    order.shippingDate = new Date();
  }

  if (stepType === 'deliver') {
    order.status = 'delivered';
    order.deliveryDate = new Date();
  }

  return updateOrder(order);
}`,

  vulnerableLine: `if (stepType === 'ship') {`,

  options: [
    {
      code: `if (stepType === 'ship' && order.status === 'approved') {`,
      correct: true,
      explanation: `Check order approved before shipping`
    },
    {
      code: `if (stepType === 'ship') { // No workflow validation`,
      correct: false,
      explanation: 'Ships orders without approval step'
    },
    {
      code: `if (stepType === 'ship' && order.managerId) {`,
      correct: false,
      explanation: 'Checks manager exists but not approval status'
    },
    {
      code: `if (stepType === 'ship' && Date.now() > order.createdDate) {`,
      correct: false,
      explanation: 'Meaningless time check bypasses workflow'
    },
    {
      code: `if (stepType === 'ship' && order.status !== 'cancelled') {`,
      correct: false,
      explanation: 'Avoids cancelled orders but skips approval'
    },
    {
      code: `if (stepType === 'ship' && order.items.length > 0) {`,
      correct: false,
      explanation: 'Checks items exist but ignores approval'
    },
    {
      code: `if (stepType === 'ship' && userId === order.managerId) {`,
      correct: false,
      explanation: 'Manager can ship without approving first'
    },
    {
      code: `if (stepType === 'ship' && order.priority === 'high') {`,
      correct: false,
      explanation: 'High priority orders bypass approval workflow'
    },
    {
      code: `if (stepType === 'ship' && (order.status === 'approved' || order.urgent)) {`,
      correct: false,
      explanation: 'Urgent orders bypass required approval step'
    },
    {
      code: `if (stepType === 'ship') { if (order.status !== 'approved') console.log('Warning: shipping without approval'); `,
      correct: false,
      explanation: 'Logs warning but ships without approval'
    }
  ]
}