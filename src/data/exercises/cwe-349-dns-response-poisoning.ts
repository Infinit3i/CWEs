import type { Exercise } from '@/data/exercises'

/**
 * CWE-349 Exercise 3: DNS Response with Extra Records
 * Based on DNS cache poisoning attacks accepting extraneous untrusted data
 */
export const cwe349DnsResponsePoisoning: Exercise = {
  cweId: 'CWE-349',
  name: 'DNS Response Poisoning - Extra Record Acceptance',
  language: 'JavaScript',

  vulnerableFunction: `function processDnsResponse(query, dnsResponse) {
  const cache = {};

  // Process the DNS response from trusted server
  if (dnsResponse.header.authoritative) {
    // Cache all records from the response
    for (const section of ['answers', 'authority', 'additional']) {
      if (dnsResponse[section]) {
        for (const record of dnsResponse[section]) {
          const key = record.name + ':' + record.type;
          cache[key] = {
            data: record.data,
            ttl: record.ttl,
            timestamp: Date.now()
          };
        }
      }
    }

    // Return the requested record
    const requestedKey = query.name + ':' + query.type;
    return cache[requestedKey];
  }

  return null;
}`,

  vulnerableLine: `cache[key] = {`,

  options: [
    {
      code: `// Only cache records that were explicitly requested or are authoritative for the domain
const queryDomain = extractDomain(query.name);
for (const record of dnsResponse[section]) {
  if (record.name === query.name && record.type === query.type) {
    // Only cache the exact record that was requested
    const key = record.name + ':' + record.type;
    cache[key] = { data: record.data, ttl: record.ttl, timestamp: Date.now() };
  }
}`,
      correct: true,
      explanation: `Validate DNS responses`
    },
    {
      code: `for (const record of dnsResponse[section]) {
  const key = record.name + ':' + record.type;
  cache[key] = {
    data: record.data,
    ttl: record.ttl,
    timestamp: Date.now()
  };
}`,
      correct: false,
      explanation: 'Caching all DNS records including additional/authority sections enables cache poisoning. Attackers can inject malicious records for unrelated domains (CAPEC-142).'
    },
    {
      code: `if (section === 'answers') {
  for (const record of dnsResponse[section]) {
    const key = record.name + ':' + record.type;
    cache[key] = { data: record.data, ttl: record.ttl, timestamp: Date.now() };
  }
}`,
      correct: false,
      explanation: 'Restricting to answers section helps but is insufficient. Malicious records can be placed in the answers section for domains not requested.'
    },
    {
      code: `for (const record of dnsResponse[section]) {
  if (record.name.endsWith('.com')) {
    const key = record.name + ':' + record.type;
    cache[key] = { data: record.data, ttl: record.ttl, timestamp: Date.now() };
  }
}`,
      correct: false,
      explanation: 'TLD filtering does not prevent cache poisoning. Attackers can poison any .com domain records, not just the one requested.'
    },
    {
      code: `for (const record of dnsResponse[section]) {
  if (record.ttl > 0 && record.ttl < 3600) {
    const key = record.name + ':' + record.type;
    cache[key] = { data: record.data, ttl: record.ttl, timestamp: Date.now() };
  }
}`,
      correct: false,
      explanation: 'TTL validation does not prevent cache poisoning. Attackers can use valid TTL values while still injecting malicious domain records.'
    },
    {
      code: `if (dnsResponse[section].length <= 10) {
  for (const record of dnsResponse[section]) {
    const key = record.name + ':' + record.type;
    cache[key] = { data: record.data, ttl: record.ttl, timestamp: Date.now() };
  }
}`,
      correct: false,
      explanation: 'Limiting number of records does not prevent cache poisoning. A few carefully crafted malicious records can be highly effective.'
    },
    {
      code: `for (const record of dnsResponse[section]) {
  try {
    const key = record.name + ':' + record.type;
    cache[key] = { data: record.data, ttl: record.ttl, timestamp: Date.now() };
  } catch (e) {
    continue;
  }
}`,
      correct: false,
      explanation: 'Error handling does not prevent cache poisoning. Valid malicious records will not throw exceptions during processing.'
    },
    {
      code: `for (const record of dnsResponse[section]) {
  if (isValidDnsName(record.name)) {
    const key = record.name + ':' + record.type;
    cache[key] = { data: record.data, ttl: record.ttl, timestamp: Date.now() };
  }
}`,
      correct: false,
      explanation: 'DNS name validation does not prevent cache poisoning. Attackers use valid DNS names for domains they want to poison.'
    },
    {
      code: `const uniqueRecords = new Set();
for (const record of dnsResponse[section]) {
  const recordKey = record.name + record.type + record.data;
  if (!uniqueRecords.has(recordKey)) {
    uniqueRecords.add(recordKey);
    const key = record.name + ':' + record.type;
    cache[key] = { data: record.data, ttl: record.ttl, timestamp: Date.now() };
  }
}`,
      correct: false,
      explanation: 'Deduplication does not prevent cache poisoning. The issue is accepting records for domains not requested, not duplicate records.'
    },
    {
      code: `for (const record of dnsResponse[section]) {
  if (record.type === query.type) {
    const key = record.name + ':' + record.type;
    cache[key] = { data: record.data, ttl: record.ttl, timestamp: Date.now() };
  }
}`,
      correct: false,
      explanation: 'Type matching alone is insufficient. Attackers can inject records of the correct type for different domains than the one requested.'
    }
  ]
}