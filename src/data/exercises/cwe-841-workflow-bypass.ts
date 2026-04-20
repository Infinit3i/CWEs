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
      explanation: `Correct! Enforces the required workflow sequence where orders must be approved before shipping. This prevents workflow bypass where items could be shipped without proper authorization, maintaining business process integrity.`
    },
    {
      code: `if (stepType === 'ship') { // No workflow validation`,
      correct: false,
      explanation: 'Direct MITRE workflow bypass pattern. Orders can be shipped without approval, violating business processes and potentially causing unauthorized shipments or compliance violations.'
    },
    {
      code: `if (stepType === 'ship' && order.managerId) {`,
      correct: false,
      explanation: 'Checks for manager assignment but not approval status. Orders with managers can be shipped without actual approval, bypassing the critical authorization workflow step.'
    },
    {
      code: `if (stepType === 'ship' && Date.now() > order.createdDate) {`,
      correct: false,
      explanation: 'Time-based check is always true and meaningless. Orders can be shipped immediately after creation without any approval workflow, completely bypassing business authorization.'
    },
    {
      code: `if (stepType === 'ship' && order.status !== 'cancelled') {`,
      correct: false,
      explanation: 'Prevents shipping cancelled orders but allows shipping unapproved orders. The workflow bypass allows orders to skip from pending directly to shipped without proper authorization.'
    },
    {
      code: `if (stepType === 'ship' && order.items.length > 0) {`,
      correct: false,
      explanation: 'Validates order contents but ignores workflow state. Orders with items can be shipped regardless of approval status, violating the mandatory approval business process.'
    },
    {
      code: `if (stepType === 'ship' && userId === order.managerId) {`,
      correct: false,
      explanation: 'Requires manager to ship but not approval status. Managers can ship orders they haven\'t formally approved, bypassing the documented approval workflow step.'
    },
    {
      code: `if (stepType === 'ship' && order.priority === 'high') {`,
      correct: false,
      explanation: 'Priority-based shipping bypasses approval workflow. High priority orders can skip approval entirely, creating inconsistent business processes and potential unauthorized shipments.'
    },
    {
      code: `if (stepType === 'ship' && (order.status === 'approved' || order.urgent)) {`,
      correct: false,
      explanation: 'Creates dual workflow paths where urgent orders bypass approval. This inconsistency violates business process integrity and creates authorization loopholes for marking orders urgent.'
    },
    {
      code: `if (stepType === 'ship') { if (order.status !== 'approved') console.log('Warning: shipping without approval'); `,
      correct: false,
      explanation: 'Logs warning but allows workflow bypass. Orders are shipped without approval while only generating log entries, failing to enforce the required business workflow sequence.'
    }
  ]
}