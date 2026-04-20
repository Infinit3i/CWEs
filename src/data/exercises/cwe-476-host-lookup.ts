import type { Exercise } from '@/data/exercises'

/**
 * CWE-476 exercise - Host Lookup Function
 * Based on MITRE demonstrative C example for NULL pointer dereference
 */
export const cwe476HostLookup: Exercise = {
  cweId: 'CWE-476',
  name: 'NULL Pointer Dereference - Host Lookup Function',

  vulnerableFunction: `function hostLookup(userSuppliedAddr) {
  let hostname = '';

  // Validate address format
  validateAddrForm(userSuppliedAddr);
  const addr = inet_addr(userSuppliedAddr);

  // Lookup host information
  const hp = gethostbyaddr(addr, 4, AF_INET);
  hostname = hp.h_name; // Potential null dereference

  return hostname;
}`,

  vulnerableLine: `hostname = hp.h_name;`,

  options: [
    {
      code: `const hp = gethostbyaddr(addr, 4, AF_INET); if (hp === null || hp === undefined) { throw new Error('Host lookup failed'); } hostname = hp.h_name;`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    {
      code: `void host_lookup(char *user_supplied_addr) { struct hostent *hp; hp = gethostbyaddr(addr, sizeof(struct in_addr), AF_INET); strcpy(hostname, hp->h_name); }`,
      correct: false,
      explanation: '"If gethostbyaddr() fails, it returns NULL" but the code proceeds to dereference NULL in strcpy(), causing a crash when hp->h_name is accessed.'
    },
    {
      code: `const hp = gethostbyaddr(addr, 4, AF_INET); try { hostname = hp.h_name; } catch (e) { hostname = "unknown"; }`,
      correct: false,
      explanation: 'Try-catch blocks cannot prevent NULL pointer dereferences in languages like C/C++. The crash occurs at the memory access level before exceptions can be thrown.'
    },
    {
      code: `const hp = gethostbyaddr(addr, 4, AF_INET); if (addr !== 0) { hostname = hp.h_name; }`,
      correct: false,
      explanation: 'Validating the input address does not prevent NULL return values from gethostbyaddr(). The function can still fail and return NULL even with valid input addresses.'
    },
    {
      code: `const hp = gethostbyaddr(addr, 4, AF_INET); setTimeout(() => { hostname = hp.h_name; }, 100);`,
      correct: false,
      explanation: 'Delaying access does not prevent NULL pointer dereference. If gethostbyaddr() returns NULL, waiting will not change the NULL value to a valid pointer.'
    },
    {
      code: `let hp; try { hp = gethostbyaddr(addr, 4, AF_INET); } finally { hostname = hp.h_name; }`,
      correct: false,
      explanation: 'Finally blocks execute regardless of success or failure. This guarantees the NULL dereference will occur if gethostbyaddr() fails, making it worse than the original code.'
    },
    {
      code: `const hp = gethostbyaddr(addr, 4, AF_INET); if (typeof hp === 'object') { hostname = hp.h_name; }`,
      correct: false,
      explanation: 'Type checking is insufficient because NULL is also of type "object" in JavaScript. This check would still allow NULL values to pass through and cause errors.'
    },
    {
      code: `const hp = gethostbyaddr(addr, 4, AF_INET); hostname = hp && hp.h_name ? hp.h_name : '';`,
      correct: false,
      explanation: 'While this prevents the crash by using short-circuit evaluation, it is less explicit than proper null checking and may not be clear to other developers reading the code.'
    },
    {
      code: `const hp = gethostbyaddr(addr, 4, AF_INET); if (hp.constructor === Object) { hostname = hp.h_name; }`,
      correct: false,
      explanation: 'Constructor checking will throw an error when attempting to access the constructor property of a NULL value, causing the same type of crash we are trying to prevent.'
    },
    {
      code: `const hp = gethostbyaddr(addr, 4, AF_INET); hostname = JSON.stringify(hp.h_name);`,
      correct: false,
      explanation: 'JSON.stringify() will still attempt to access hp.h_name first, causing a NULL pointer dereference before the stringify operation can handle any NULL values.'
    }
  ]
}