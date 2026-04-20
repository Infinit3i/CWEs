import type { Exercise } from '@/data/exercises'

export const cwe416ErrorLogging: Exercise = {
  cweId: 'CWE-416',
  name: 'Use After Free - Error Context Logging',
  language: 'Rust',

  vulnerableFunction: `function processTransaction(transactionData) {
  let contextBuffer = allocateTransactionContext(transactionData.size);
  let abortOperation = false;

  try {
    // Initialize transaction context
    setupTransactionContext(contextBuffer, transactionData);

    // Validate transaction
    if (!validateTransaction(transactionData)) {
      abortOperation = true;
      deallocateTransactionContext(contextBuffer);
      throw new Error('Transaction validation failed');
    }

    // Process transaction
    return executeTransaction(contextBuffer);

  } catch (error) {
    if (abortOperation) {
      logError('Transaction aborted before commit', contextBuffer);
    }
    throw error;
  }
}`,

  vulnerableLine: `logError('Transaction aborted before commit', contextBuffer);`,

  options: [
    {
      code: `if (abortOperation && !isContextFreed(contextBuffer)) { logError('Transaction aborted', contextBuffer); }`,
      correct: true,
      explanation: `Check if buffer is freed before access`
    },
    {
      code: `logError('Transaction aborted before commit', contextBuffer);`,
      correct: false,
      explanation: 'Using freed buffer causes crash or data leak'
    },
    {
      code: `logError('Transaction aborted before commit', null);`,
      correct: false,
      explanation: 'Passing null loses debugging context'
    },
    {
      code: `if (!abortOperation) { logError('Transaction aborted before commit', contextBuffer); }`,
      correct: false,
      explanation: 'Inverted logic prevents logging when needed'
    },
    {
      code: `try { logError('Transaction aborted before commit', contextBuffer); } catch(e) { /* ignore */ }`,
      correct: false,
      explanation: 'Exception handling after use-after-free is too late. Memory access to freed buffer occurs before exceptions can prevent the vulnerability.'
    },
    {
      code: `contextBuffer = allocateTransactionContext(transactionData.size); logError('Transaction aborted', contextBuffer);`,
      correct: false,
      explanation: 'Reallocating in error handler wastes resources and may fail under error conditions. Also changes the context being logged from the original transaction.'
    },
    {
      code: `if (contextBuffer) { logError('Transaction aborted before commit', contextBuffer); }`,
      correct: false,
      explanation: 'Truthy check insufficient for freed memory. Deallocated pointers often retain their address value, appearing truthy while pointing to invalid memory.'
    },
    {
      code: `logError('Transaction aborted before commit', JSON.stringify(transactionData));`,
      correct: false,
      explanation: 'Using original data avoids use-after-free but loses processed transaction state information that could be crucial for debugging the failure.'
    },
    {
      code: `setTimeout(() => logError('Transaction aborted', contextBuffer), 100);`,
      correct: false,
      explanation: 'Delayed logging does not solve use-after-free. The buffer remains freed and may be reallocated for other purposes, making delayed access even more dangerous.'
    },
    {
      code: `if (typeof contextBuffer === 'object') { logError('Transaction aborted', contextBuffer); }`,
      correct: false,
      explanation: 'Type checking does not detect freed memory. Freed buffer pointers remain object references pointing to invalid/reallocated memory locations.'
    }
  ]
}