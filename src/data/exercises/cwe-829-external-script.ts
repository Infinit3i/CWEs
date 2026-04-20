import type { Exercise } from '@/data/exercises'

/**
 * CWE-829: Inclusion of Functionality from Untrusted Control Sphere - External Script Loading
 * Based on MITRE weather widget example where external JavaScript can be compromised
 */
export const cwe829ExternalScript: Exercise = {
  cweId: 'CWE-829',
  name: 'Inclusion of Functionality from Untrusted Control Sphere - Widget Integration',

  vulnerableFunction: `function loadDashboardWidgets(widgetConfigs) {
  const dashboardContainer = document.getElementById('dashboard');

  widgetConfigs.forEach(config => {
    // Create widget container
    const widgetDiv = document.createElement('div');
    widgetDiv.id = config.name;
    widgetDiv.className = 'widget';

    // Load external widget script
    const script = document.createElement('script');
    script.src = config.scriptUrl;
    script.onload = () => {
      console.log(\`Widget \${config.name} loaded successfully\`);
    };

    document.head.appendChild(script);
    dashboardContainer.appendChild(widgetDiv);
  });
}`,

  vulnerableLine: `script.src = config.scriptUrl;`,

  options: [
    {
      code: `if (isAllowlistedDomain(config.scriptUrl)) { script.src = config.scriptUrl; } else { throw new Error('Untrusted domain'); }`,
      correct: true,
      explanation: `Correct! Validates script sources against a domain allowlist before loading external functionality. This prevents malicious script injection from compromised or untrusted domains that could execute arbitrary code in the application context.`
    },
    {
      code: `script.src = config.scriptUrl; // Load any external script`,
      correct: false,
      explanation: 'Direct MITRE vulnerability pattern. Loading scripts from arbitrary URLs allows attackers to inject malicious JavaScript if they compromise external domains or provide malicious script URLs.'
    },
    {
      code: `script.src = config.scriptUrl.startsWith('https://') ? config.scriptUrl : 'about:blank';`,
      correct: false,
      explanation: 'HTTPS check doesn\'t validate trust boundaries. Attackers can host malicious scripts on HTTPS domains, and the protocol security doesn\'t prevent code injection from untrusted sources.'
    },
    {
      code: `const encodedUrl = encodeURIComponent(config.scriptUrl); script.src = encodedUrl;`,
      correct: false,
      explanation: 'URL encoding breaks script loading functionality and doesn\'t address the trust issue. The encoded URL won\'t function as a script source and still represents untrusted content.'
    },
    {
      code: `script.src = config.scriptUrl; script.crossOrigin = 'anonymous';`,
      correct: false,
      explanation: 'CORS settings don\'t prevent malicious script execution. The crossOrigin attribute affects resource sharing but doesn\'t validate whether the external script is trusted or safe.'
    },
    {
      code: `if (config.scriptUrl.length < 200) script.src = config.scriptUrl;`,
      correct: false,
      explanation: 'Length validation doesn\'t address trust boundaries. Short URLs can still point to malicious scripts, and URL length has no correlation with script safety or trustworthiness.'
    },
    {
      code: `const sanitizedUrl = config.scriptUrl.replace(/[^a-zA-Z0-9/:.-]/g, ''); script.src = sanitizedUrl;`,
      correct: false,
      explanation: 'Character sanitization doesn\'t validate trust. Sanitized URLs can still point to malicious domains, and removing special characters doesn\'t prevent code injection from untrusted sources.'
    },
    {
      code: `script.src = config.scriptUrl; script.integrity = config.integrity || '';`,
      correct: false,
      explanation: 'Integrity checks are good practice but incomplete without hash validation. If the integrity value is also client-controlled or missing, it provides no protection against malicious scripts.'
    },
    {
      code: `if (!config.scriptUrl.includes('malicious')) script.src = config.scriptUrl;`,
      correct: false,
      explanation: 'Keyword filtering is easily bypassable. Attackers use legitimate-looking domains or paths that don\'t contain obvious malicious keywords but still host harmful code.'
    },
    {
      code: `script.src = config.scriptUrl; script.sandbox = 'allow-scripts';`,
      correct: false,
      explanation: 'Sandbox attribute applies to iframes, not script tags. The sandbox doesn\'t prevent malicious script execution, and script tags execute with full page privileges regardless.'
    }
  ]
}