import type { Exercise } from '@/data/exercises'

/**
 * CWE-829: Inclusion of Functionality from Untrusted Control Sphere - Dynamic Library Import
 * Runtime library loading from user-specified sources
 */
export const cwe829LibraryImport: Exercise = {
  cweId: 'CWE-829',
  name: 'Inclusion of Functionality from Untrusted Control Sphere - Library Loading',
  language: 'JavaScript',

  vulnerableFunction: `async function loadUserLibrary(libraryConfig, userContext) {
  const { libraryPath, moduleName, version } = libraryConfig;

  // Construct library URL
  const libraryUrl = \`https://cdn.example.com/\${libraryPath}/\${version}/\${moduleName}.js\`;

  try {
    // Dynamic import from user-specified path
    const libraryModule = await import(libraryUrl);

    // Initialize library with user context
    if (libraryModule.default && typeof libraryModule.default.init === 'function') {
      await libraryModule.default.init(userContext);
    }

    // Store library reference for later use
    global.userLibraries = global.userLibraries || {};
    global.userLibraries[moduleName] = libraryModule;

    return {
      success: true,
      module: libraryModule,
      message: \`Library \${moduleName} loaded successfully\`
    };

  } catch (error) {
    return {
      success: false,
      error: \`Failed to load library: \${error.message}\`
    };
  }
}`,

  vulnerableLine: `const libraryModule = await import(libraryUrl);`,

  options: [
    {
      code: `if (isApprovedLibrary(moduleName, version)) { const libraryModule = await import(getApprovedLibraryUrl(moduleName, version)); } else { throw new Error('Library not approved'); }`,
      correct: true,
      explanation: `Validate library sources`
    },
    {
      code: `const libraryModule = await import(libraryUrl); // Load any library`,
      correct: false,
      explanation: 'Direct MITRE vulnerability pattern. Dynamic imports from user-controlled URLs allow loading malicious libraries from compromised CDNs or attacker-controlled domains, executing untrusted code with application privileges.'
    },
    {
      code: `if (libraryUrl.startsWith('https://cdn.example.com/')) { const libraryModule = await import(libraryUrl); }`,
      correct: false,
      explanation: 'Domain restriction helps but user controls the path. Attackers can exploit path traversal or subdomain takeover on the trusted domain to host malicious libraries.'
    },
    {
      code: `const sanitizedUrl = libraryUrl.replace(/[^a-zA-Z0-9/:.-]/g, ''); const libraryModule = await import(sanitizedUrl);`,
      correct: false,
      explanation: 'Character filtering doesn\'t address trust boundaries. Sanitized URLs can still point to malicious libraries hosted on compromised or attacker-controlled domains.'
    },
    {
      code: `if (version.match(/^\\d+\\.\\d+\\.\\d+$/)) { const libraryModule = await import(libraryUrl); }`,
      correct: false,
      explanation: 'Version format validation doesn\'t prevent malicious libraries. Valid semantic versions can still reference libraries containing malicious code or vulnerabilities.'
    },
    {
      code: `const cachedUrl = getCachedLibraryUrl(libraryUrl); const libraryModule = await import(cachedUrl || libraryUrl);`,
      correct: false,
      explanation: 'Caching fallback doesn\'t solve trust issues. If the cache misses, untrusted URLs are still used, and cached malicious libraries remain dangerous.'
    },
    {
      code: `try { const libraryModule = await import(libraryUrl); } catch(e) { console.log('Import failed safely'); }`,
      correct: false,
      explanation: 'Exception handling doesn\'t prevent malicious execution. If the import succeeds, the untrusted code executes with full privileges before any safety checks can occur.'
    },
    {
      code: `const timeoutPromise = new Promise((_, reject) => setTimeout(() => reject('timeout'), 5000)); const libraryModule = await Promise.race([import(libraryUrl), timeoutPromise]);`,
      correct: false,
      explanation: 'Timeout restrictions don\'t address trust boundaries. Fast-loading malicious libraries can execute harmful code well within timeout limits, and timing doesn\'t validate safety.'
    },
    {
      code: `if (moduleName.length > 3) { const libraryModule = await import(libraryUrl); }`,
      correct: false,
      explanation: 'Name length validation is arbitrary and irrelevant to security. Short or long module names can both reference malicious libraries from untrusted sources.'
    },
    {
      code: `const libraryModule = await import(libraryUrl + '?v=' + Date.now());`,
      correct: false,
      explanation: 'Cache-busting parameters don\'t improve security. Adding timestamps to untrusted URLs still results in loading potentially malicious code from unverified sources.'
    }
  ]
}