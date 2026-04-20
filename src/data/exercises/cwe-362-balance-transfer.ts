import type { Exercise } from '@/data/exercises'

/**
 * CWE-362: Race Condition in Bank Transfer Service
 * Enterprise scenario: Financial transaction processing with concurrent access issues
 */
export const cwe362BalanceTransfer: Exercise = {
  cweId: 'CWE-362',
  name: 'Race Condition - Bank Transfer Service',

  vulnerableFunction: `class TransferService {
  async processTransfer(fromAccount: string, toAccount: string, amount: number) {
    // Get current balance
    const currentBalance = await this.getAccountBalance(fromAccount);

    if (currentBalance < amount) {
      throw new Error('Insufficient funds');
    }

    // Calculate new balance
    const newBalance = currentBalance - amount;

    // Update account balance
    await this.updateAccountBalance(fromAccount, newBalance);

    // Add to destination account
    const destBalance = await this.getAccountBalance(toAccount);
    await this.updateAccountBalance(toAccount, destBalance + amount);

    return {
      fromAccount,
      toAccount,
      amount,
      newBalance,
      timestamp: new Date()
    };
  }
}`,

  vulnerableLine: `const currentBalance = await this.getAccountBalance(fromAccount);`,

  options: [
    {
      code: `await this.acquireAccountLock(fromAccount); try { const currentBalance = await this.getAccountBalance(fromAccount);`,
      correct: true,
      explanation: `Correct! Account-level locking prevents race conditions in financial transactions. This ensures the entire read-validate-update sequence is atomic, preventing money creation through concurrent transfers.`
    },
    {
      code: `const currentBalance = await this.getAccountBalance(fromAccount);`,
      correct: false,
      explanation: 'From MITRE: Race condition allows concurrent requests to read the same balance before either updates it. Two $80 transfers from $100 balance can both succeed, creating money instead of preventing overdraft.'
    },
    {
      code: `const currentBalance = await this.getAccountBalance(fromAccount); await new Promise(resolve => setTimeout(resolve, 100));`,
      correct: false,
      explanation: 'Adding delays worsens race conditions by extending the vulnerable window. This increases the likelihood of concurrent access issues rather than solving them.'
    },
    {
      code: `const currentBalance = await this.getAccountBalance(fromAccount); if (Math.random() > 0.5) await new Promise(resolve => setTimeout(resolve, 50));`,
      correct: false,
      explanation: 'Random delays do not prevent race conditions. The read-modify-write sequence remains non-atomic, allowing concurrent transactions to interfere with each other.'
    },
    {
      code: `const balanceCheck = await Promise.all([this.getAccountBalance(fromAccount), this.getAccountBalance(fromAccount)]); const currentBalance = balanceCheck[0];`,
      correct: false,
      explanation: 'Multiple balance reads do not solve race conditions. Both reads can return the same value before any update occurs, maintaining the vulnerable timing window.'
    },
    {
      code: `const currentBalance = await this.getAccountBalance(fromAccount); console.log(\`Processing transfer for balance: \${currentBalance}\`);`,
      correct: false,
      explanation: 'Logging does not address race conditions. The fundamental issue of non-atomic read-modify-write operations remains, allowing concurrent access problems.'
    },
    {
      code: `const currentBalance = await this.getAccountBalance(fromAccount); if (currentBalance === 0) { await new Promise(resolve => setTimeout(resolve, 1000)); }`,
      correct: false,
      explanation: 'Conditional delays based on balance value do not prevent race conditions. The timing window for concurrent access still exists regardless of balance amount.'
    },
    {
      code: `const timestamp = Date.now(); const currentBalance = await this.getAccountBalance(fromAccount); if (Date.now() - timestamp > 1000) throw new Error('Operation timeout');`,
      correct: false,
      explanation: 'Timeout mechanisms do not prevent race conditions. The read-modify-write sequence remains non-atomic, allowing interference from concurrent operations.'
    }
  ]
}