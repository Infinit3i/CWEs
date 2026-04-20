import type { Exercise } from '@/data/exercises'

/**
 * CWE-269: Improper Privilege Management in Data Access Control
 * Enterprise scenario: Customer data access with insufficient privilege validation
 */
export const cwe269DataAccess: Exercise = {
  cweId: 'CWE-269',
  name: 'Privilege Management - Customer Data Access',

  vulnerableFunction: `class CustomerDataController {
  async getCustomerData(requestingUserId: string, customerId: string, includeFinancials: boolean = false) {
    const requestingUser = await User.findById(requestingUserId);

    if (!requestingUser) {
      throw new Error('Requesting user not found');
    }

    // Check if user has access to customer data
    if (!requestingUser.permissions.includes('read_customer_data')) {
      throw new Error('No permission to access customer data');
    }

    const customerData = await Customer.findById(customerId);

    if (!customerData) {
      throw new Error('Customer not found');
    }

    let responseData = {
      customerId: customerData.id,
      name: customerData.name,
      email: customerData.email,
      phone: customerData.phone,
      address: customerData.address
    };

    // Include financial data if requested
    if (includeFinancials) {
      const financialData = await FinancialData.findOne({ customerId });
      responseData.financials = {
        accountBalance: financialData?.accountBalance,
        creditScore: financialData?.creditScore,
        transactions: financialData?.recentTransactions
      };
    }

    return responseData;
  }
}`,

  vulnerableLine: `if (!requestingUser.permissions.includes('read_customer_data')) {`,

  options: [
    {
      code: `if (!this.canAccessCustomer(requestingUser, customerId) || (includeFinancials && !this.canAccessFinancials(requestingUser, customerId))) { throw new Error('Insufficient privileges for requested data access'); }`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    {
      code: `if (!requestingUser.permissions.includes('read_customer_data')) {`,
      correct: false,
      explanation: 'Generic permission checking without validating specific data access allows users to retrieve any customer data. This violates principle of least privilege and data access segregation.'
    },
    {
      code: `if (includeFinancials && !requestingUser.permissions.includes('read_financial_data')) { throw new Error('No permission for financial data'); } if (!requestingUser.permissions.includes('read_customer_data')) {`,
      correct: false,
      explanation: 'Adding financial permission check is good but insufficient. Users can still access any customer\'s basic data and any financial data they have permission for, without customer-specific authorization.'
    },
    {
      code: `if (requestingUser.department !== 'customer_service' && requestingUser.role !== 'admin') { throw new Error('Department not authorized'); } if (!requestingUser.permissions.includes('read_customer_data')) {`,
      correct: false,
      explanation: 'Department-based restrictions are too broad. Customer service staff should not automatically access all customer data; they should only access data for customers they are authorized to help.'
    },
    {
      code: `const isOwner = customerData.assignedRepresentative === requestingUserId; if (!isOwner && requestingUser.role !== 'admin') { throw new Error('Not assigned to this customer'); }`,
      correct: false,
      explanation: 'Representative assignment checking is better but still incomplete. It does not validate permission types, and the base permission check is missing, allowing unauthorized access through role escalation.'
    },
    {
      code: `if (includeFinancials && customerData.accountType === 'premium' && requestingUser.role !== 'senior_analyst') { throw new Error('Premium account access denied'); }`,
      correct: false,
      explanation: 'Account-type restrictions add granularity but do not address the fundamental privilege validation issue. Users can still access inappropriate data based on incomplete authorization checks.'
    },
    {
      code: `const accessTime = new Date(); if (accessTime.getHours() < 9 || accessTime.getHours() > 17) { throw new Error('Customer data access outside business hours'); }`,
      correct: false,
      explanation: 'Time-based restrictions improve security but do not address privilege validation. The core issue of insufficient authorization checking for specific customer and data access remains.'
    },
    {
      code: `if (requestingUser.lastPasswordChange && (Date.now() - requestingUser.lastPasswordChange.getTime()) > 7776000000) { throw new Error('Password too old for data access'); }`,
      correct: false,
      explanation: 'Password age requirements enhance authentication security but do not fix privilege validation. Users can still access unauthorized customer data with recently changed passwords.'
    }
  ]
}