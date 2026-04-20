import type { Exercise } from '@/data/exercises'

export const cwe416CacheInvalidation: Exercise = {
  cweId: 'CWE-416',
  name: 'Use After Free - Cache Entry Management',

  vulnerableFunction: `function manageCacheEntry(cacheKey, operation) {
  let cacheEntry = getCacheEntry(cacheKey);

  switch (operation) {
    case 'invalidate':
      invalidateCacheEntry(cacheEntry);
      deallocateCacheEntry(cacheEntry);
      break;

    case 'refresh':
      updateCacheTimestamp(cacheEntry);
      break;

    case 'expire':
      if (isCacheExpired(cacheEntry)) {
        deallocateCacheEntry(cacheEntry);
      }
      break;

    case 'access':
      incrementAccessCount(cacheEntry);
      break;
  }

  // Update cache statistics
  updateCacheStatistics(cacheEntry, operation);

  return { operation, key: cacheKey, timestamp: Date.now() };
}`,

  vulnerableLine: `updateCacheStatistics(cacheEntry, operation);`,

  options: [
    {
      code: `if (operation !== 'invalidate' && !(operation === 'expire' && isCacheExpired(cacheEntry))) { updateCacheStatistics(cacheEntry, operation); }`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    {
      code: `updateCacheStatistics(cacheEntry, operation);`,
      correct: false,
Use after free causes crashes'
    },
    {
      code: `if (operation !== "invalidate") { updateCacheStatistics(cacheEntry, operation); }`,
      correct: false,
      explanation: 'Incomplete check misses the expire case. When cache expires and gets deallocated, statistics update still accesses freed memory, causing use-after-free vulnerability.'
    },
    {
      code: `updateCacheStatistics(null, operation);`,
      correct: false,
      explanation: 'Passing null avoids use-after-free but loses valuable cache performance data needed for optimization and monitoring decisions.'
    },
    {
      code: `try { updateCacheStatistics(cacheEntry, operation); } catch(e) { updateCacheStatistics({}, operation); }`,
      correct: false,
      explanation: 'Exception handling after use-after-free is too late. Memory access to freed cache entry occurs before exception handling can prevent the vulnerability.'
    },
    {
      code: `if (cacheEntry !== null) { updateCacheStatistics(cacheEntry, operation); }`,
      correct: false,
      explanation: 'Null check insufficient for freed memory. Deallocated cache entry pointers often retain their reference value while pointing to invalid memory.'
    },
    {
      code: `cacheEntry = getCacheEntry(cacheKey); updateCacheStatistics(cacheEntry, operation);`,
      correct: false,
      explanation: 'Re-fetching after potential deallocation may return null or different cache entry, providing inaccurate statistics for the actual operation performed.'
    },
    {
      code: `const entryCopy = {...cacheEntry}; updateCacheStatistics(entryCopy, operation);`,
      correct: false,
      explanation: 'Copying before operations works but creates performance overhead and memory waste. Better to track entry validity throughout the function.'
    },
    {
      code: `setTimeout(() => updateCacheStatistics(cacheEntry, operation), 0);`,
      correct: false,
      explanation: 'Delayed statistics update does not solve use-after-free. Cache entry remains freed and may be reallocated, making delayed access dangerous.'
    },
    {
      code: `if (typeof cacheEntry === "object") { updateCacheStatistics(cacheEntry, operation); }`,
      correct: false,
      explanation: 'Type checking does not detect freed memory. Freed cache entries remain object type references pointing to invalid/reallocated memory locations.'
    }
  ]
}