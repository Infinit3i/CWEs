import type { Exercise } from '@/data/exercises'

/**
 * CWE-829: Inclusion of Functionality from Untrusted Control Sphere - Dynamic Plugin Loading
 * Untrusted plugin/module loading that can execute malicious code
 */
export const cwe829PluginLoading: Exercise = {
  cweId: 'CWE-829',
  name: 'Inclusion of Functionality from Untrusted Control Sphere - Plugin System',

  vulnerableFunction: `async function loadUserPlugin(pluginConfig, userId) {
  const { pluginUrl, pluginName, pluginVersion } = pluginConfig;

  try {
    // Download plugin code
    const response = await fetch(pluginUrl);
    const pluginCode = await response.text();

    // Create plugin execution context
    const pluginFunction = new Function('exports', 'require', 'console', pluginCode);

    // Set up plugin environment
    const pluginExports = {};
    const pluginRequire = (module) => {
      // Simplified require for plugins
      return require(module);
    };

    // Execute plugin code
    pluginFunction(pluginExports, pluginRequire, console);

    // Register plugin
    registerPlugin(pluginName, pluginExports, userId);
    return { success: true, message: 'Plugin loaded successfully' };

  } catch (error) {
    return { success: false, error: error.message };
  }
}`,

  vulnerableLine: `const pluginFunction = new Function('exports', 'require', 'console', pluginCode);`,

  options: [
    {
      code: `if (!isSignedPlugin(pluginCode, pluginConfig.signature)) { throw new Error('Invalid plugin signature'); } const pluginFunction = vm.runInNewContext(pluginCode, sandbox);`,
      correct: true,
      explanation: `Correct! Validates plugin signature before execution and uses vm.runInNewContext for isolated execution. This prevents unsigned malicious code execution and limits plugin access to system resources through sandboxing.`
    },
    {
      code: `const pluginFunction = new Function('exports', 'require', 'console', pluginCode); // Execute any code`,
      correct: false,
      explanation: 'Direct MITRE vulnerability pattern. Using Function constructor with untrusted code allows arbitrary JavaScript execution with full system privileges, enabling malicious plugins to access sensitive data or perform unauthorized actions.'
    },
    {
      code: `const cleanedCode = pluginCode.replace(/eval|exec|spawn/g, ''); const pluginFunction = new Function('exports', 'require', 'console', cleanedCode);`,
      correct: false,
      explanation: 'Basic keyword filtering is insufficient. Malicious plugins can use alternative methods like setTimeout, setInterval, or indirect code execution to bypass simple string replacement filtering.'
    },
    {
      code: `if (pluginCode.length < 10000) { const pluginFunction = new Function('exports', 'require', 'console', pluginCode); }`,
      correct: false,
      explanation: 'Size limitations don\'t prevent malicious code execution. Small plugins can still contain harmful functionality, and code size has no correlation with safety or trustworthiness.'
    },
    {
      code: `const pluginFunction = new Function('exports', 'limitedRequire', 'console', pluginCode); // Limited require function`,
      correct: false,
      explanation: 'Custom require function helps but Function constructor still allows arbitrary code execution. Malicious plugins can bypass require limitations through other JavaScript features and APIs.'
    },
    {
      code: `if (pluginConfig.trusted) { const pluginFunction = new Function('exports', 'require', 'console', pluginCode); }`,
      correct: false,
      explanation: 'Trust flag is likely client-controlled and doesn\'t validate actual trustworthiness. Attackers can set trusted=true in plugin configurations to bypass this superficial check.'
    },
    {
      code: `const base64Code = btoa(pluginCode); const pluginFunction = new Function('exports', 'require', 'console', atob(base64Code));`,
      correct: false,
      explanation: 'Base64 encoding provides no security benefit for code execution. The encoded malicious code becomes the same dangerous code after decoding and execution.'
    },
    {
      code: `try { const pluginFunction = new Function('exports', 'require', 'console', pluginCode); } catch(e) { console.log('Safe execution'); }`,
      correct: false,
      explanation: 'Try-catch doesn\'t prevent malicious code execution. If the Function constructor succeeds, the malicious code will execute with full privileges before any exceptions occur.'
    },
    {
      code: `const minifiedCode = pluginCode.replace(/\\s+/g, ' '); const pluginFunction = new Function('exports', 'require', 'console', minifiedCode);`,
      correct: false,
      explanation: 'Code minification doesn\'t affect security. Malicious functionality remains intact after whitespace removal, and the untrusted code still executes with full system access.'
    },
    {
      code: `setTimeout(() => { const pluginFunction = new Function('exports', 'require', 'console', pluginCode); }, 1000);`,
      correct: false,
      explanation: 'Delayed execution doesn\'t improve security. The malicious code still executes after the timeout with the same dangerous privileges and access to system resources.'
    }
  ]
}