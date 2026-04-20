import type { Exercise } from '@/data/exercises'

/**
 * CWE-94 Code Injection - Dynamic Code Generation
 * Based on MITRE demonstrative example DX-31 (Perl eval)
 */
export const cwe94Template: Exercise = {
  cweId: 'CWE-94',
  name: 'Code Injection - Template Engine',

  vulnerableFunction: `function renderTemplate(templateName, data) {
  const templateCode = \`
    function render() {
      return \`<div class="\${data.className}">\${data.content}</div>\`;
    }
    return render();
  \`;
  return eval(templateCode);
}`,

  vulnerableLine: `return eval(templateCode);`,

  options: [
    {
      code: `const allowedTemplates = { 'user': userTemplate, 'admin': adminTemplate };
const template = allowedTemplates[templateName];
if (!template) throw new Error('Invalid template');
return template(data);`,
      correct: true,
      explanation: `Correct! This uses a predefined allowlist of template functions instead of dynamic code generation. Each template is a pre-compiled function, eliminating the need for eval() and preventing code injection through template parameters.`
    },
    // MITRE-inspired wrong answers
    {
      code: `const templateCode = \`function render() { return \`<div class="\${data.className}">\${data.content}</div>\`; } return render();\`;
return eval(templateCode);`,
      correct: false,
      explanation: 'Based on MITRE DX-31: Dynamic code generation with eval() allows injection. An attacker can manipulate data.content to include "}; system("rm -rf *"); {" to break out and execute commands.'
    },
    {
      code: `const sanitized = templateName.replace(/[^a-zA-Z0-9]/g, '');
const templateCode = \`function \${sanitized}() { return data.content; }\`;
return eval(templateCode);`,
      correct: false,
      explanation: 'Character sanitization does not prevent injection through other parameters. The data.content can still contain executable JavaScript that gets evaluated in the template context.'
    },
    {
      code: `if (templateName.includes('eval') || templateName.includes('function')) {
  throw new Error('Blocked');
}
return eval(\`render_\${templateName}(data)\`);`,
      correct: false,
      explanation: 'Keyword blacklisting is easily bypassed. Attackers can use encoded characters, constructor calls, or indirect references to achieve code execution without trigger words.'
    },
    {
      code: `const vm = require('vm');
const context = { data: data };
return vm.runInContext(\`(\${templateName})\`, context);`,
      correct: false,
      explanation: 'VM contexts provide limited protection but can be escaped. If templateName contains constructor references or prototype manipulation, attackers can break out of the sandbox.'
    },
    {
      code: `try {
  return Function('data', 'return \`<div>\${data.content}</div>\`')(data);
} catch (e) {
  return 'Error rendering template';
}`,
      correct: false,
      explanation: 'Function constructor is nearly as dangerous as eval(). If data.content contains ${constructor.constructor("code")()}, attackers can execute arbitrary JavaScript through template literal injection.'
    },
    {
      code: `const template = templateName.substring(0, 20);
return eval(\`render_\${template}(data)\`);`,
      correct: false,
      explanation: 'Length truncation does not prevent code injection. Short payloads like "x();alert(1)//" can be very effective within character limits when combined with comment syntax.'
    },
    {
      code: `const escaped = templateName.replace(/'/g, "\\'").replace(/"/g, '\\"');
return eval(\`render_\${escaped}(data)\`);`,
      correct: false,
      explanation: 'Quote escaping alone is insufficient. Attackers can use backticks for template literals, or construct payloads using String.fromCharCode() without quotes.'
    },
    {
      code: `if (typeof templateName !== 'string') throw new Error('Invalid type');
return eval(\`function \${templateName}() { return data; }\`);`,
      correct: false,
      explanation: 'Type checking does not prevent injection. String inputs can still contain JavaScript syntax that gets executed when the dynamic function is evaluated.'
    },
    {
      code: `const code = \`return \`<div>\${data.content}</div>\`\`;
return new Function('data', code)(data);`,
      correct: false,
      explanation: 'New Function with user-controlled data is still vulnerable. If data.content contains template literal syntax with embedded expressions, code execution is possible.'
    }
  ]
}