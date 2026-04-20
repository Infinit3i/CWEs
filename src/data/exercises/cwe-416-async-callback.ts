import type { Exercise } from '@/data/exercises'

export const cwe416AsyncCallback: Exercise = {
  cweId: 'CWE-416',
  name: 'Use After Free - Asynchronous Resource Cleanup',

  vulnerableFunction: `function processAsyncRequest(requestData, callback) {
  let resourceHandle = allocateResource(requestData.size);

  // Setup async processing
  setupResourceData(resourceHandle, requestData);

  // Start async operation with timeout
  const timeoutId = setTimeout(() => {
    // Cleanup on timeout
    deallocateResource(resourceHandle);
    callback(new Error('Request timeout'));
  }, 5000);

  // Async processing completion
  performAsyncOperation(requestData, (result) => {
    clearTimeout(timeoutId);

    if (result.success) {
      // Process successful result using resource
      const processedData = processResultWithResource(resourceHandle, result);
      callback(null, processedData);
    } else {
      callback(new Error('Processing failed'));
    }
  });
}`,

  vulnerableLine: `const processedData = processResultWithResource(resourceHandle, result);`,

  options: [
    {
      code: `if (!isResourceFreed(resourceHandle)) { const processedData = processResultWithResource(resourceHandle, result); callback(null, processedData); } else { callback(new Error('Resource unavailable')); }`,
      correct: true,
      explanation: `Correct! Checking if the resource is still allocated before use prevents use-after-free in race conditions. If timeout occurred and freed the resource, we properly handle the error instead of accessing freed memory.`
    },
    {
      code: `const processedData = processResultWithResource(resourceHandle, result);`,
      correct: false,
      explanation: 'Classic use-after-free race condition: If timeout fires before async completion, resourceHandle is deallocated but still accessed in success callback. This can cause crashes or data corruption.'
    },
    {
      code: `try { const processedData = processResultWithResource(resourceHandle, result); callback(null, processedData); } catch(e) { callback(e); }`,
      correct: false,
      explanation: 'Exception handling cannot prevent use-after-free. Memory access to freed resource occurs before exceptions can be caught, potentially causing immediate application crash.'
    },
    {
      code: `if (resourceHandle) { const processedData = processResultWithResource(resourceHandle, result); callback(null, processedData); }`,
      correct: false,
      explanation: 'Truthy check insufficient for freed memory. Deallocated resource handles often retain their reference value while pointing to invalid memory.'
    },
    {
      code: `resourceHandle = allocateResource(requestData.size); const processedData = processResultWithResource(resourceHandle, result);`,
      correct: false,
      explanation: 'Reallocating in callback creates resource leak (original may still exist) and changes the context being processed from the original request setup.'
    },
    {
      code: `clearTimeout(timeoutId); const processedData = processResultWithResource(resourceHandle, result);`,
      correct: false,
      explanation: 'Clearing timeout prevents future deallocation but does not address race condition where timeout already fired and freed the resource before callback execution.'
    },
    {
      code: `if (timeoutId !== null) { const processedData = processResultWithResource(resourceHandle, result); callback(null, processedData); }`,
      correct: false,
      explanation: 'Checking timeout ID does not indicate resource state. Timeout may have fired and freed the resource while timeoutId remains set.'
    },
    {
      code: `const processedData = processResultWithResource(resourceHandle || {}, result);`,
      correct: false,
      explanation: 'Fallback object prevents crashes but provides invalid resource data, leading to incorrect processing results and potentially masking the underlying race condition.'
    },
    {
      code: `setTimeout(() => { const processedData = processResultWithResource(resourceHandle, result); callback(null, processedData); }, 100);`,
      correct: false,
      explanation: 'Additional delay worsens the race condition by increasing the window where timeout deallocation can occur before resource access.'
    },
    {
      code: `if (typeof resourceHandle === "object") { const processedData = processResultWithResource(resourceHandle, result); callback(null, processedData); }`,
      correct: false,
      explanation: 'Type checking does not detect freed memory. Freed resource handles remain object references pointing to invalid/reallocated memory locations.'
    }
  ]
}