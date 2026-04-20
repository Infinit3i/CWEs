import type { Exercise } from '@/data/exercises'

/**
 * CWE-829: Inclusion of Functionality from Untrusted Control Sphere - Template Loading
 * Dynamic template loading that can include malicious content
 */
export const cwe829TemplateLoading: Exercise = {
  cweId: 'CWE-829',
  name: 'Inclusion of Functionality from Untrusted Control Sphere - Template System',

  vulnerableFunction: `async function loadCustomTemplate(templateConfig, userData) {
  const { templateUrl, templateType, params } = templateConfig;

  try {
    // Fetch template from user-specified URL
    const response = await fetch(templateUrl);
    const templateContent = await response.text();

    // Process template based on type
    if (templateType === 'mustache') {
      const rendered = Mustache.render(templateContent, { user: userData, params: params });
      return rendered;
    }

    if (templateType === 'handlebars') {
      const template = Handlebars.compile(templateContent);
      return template({ user: userData, params: params });
    }

    if (templateType === 'ejs') {
      return ejs.render(templateContent, { user: userData, params: params });
    }

    // Default: treat as plain HTML
    return templateContent;

  } catch (error) {
    return \`<div class="error">Template loading failed: \${error.message}</div>\`;
  }
}`,

  vulnerableLine: `const templateContent = await response.text();`,

  options: [
    {
      code: `if (!isApprovedTemplateSource(templateUrl)) { throw new Error('Untrusted template source'); } const templateContent = await response.text(); validateTemplateContent(templateContent);`,
      correct: true,
      explanation: `Restrict template sources`
    },
    {
      code: `const templateContent = await response.text(); // Load any template`,
      correct: false,
      explanation: 'Direct MITRE vulnerability pattern. Loading templates from arbitrary URLs allows attackers to inject malicious template content with executable JavaScript or server-side code that runs in the application context.'
    },
    {
      code: `const templateContent = (await response.text()).substring(0, 5000);`,
      correct: false,
      explanation: 'Size limiting doesn\'t prevent malicious template injection. Short templates can still contain harmful script tags, template expressions, or other dangerous content within the size limit.'
    },
    {
      code: `const templateContent = (await response.text()).replace(/<script>/g, '');`,
      correct: false,
      explanation: 'Basic script tag filtering is insufficient. Malicious templates can use event handlers, encoded scripts, or template-specific expressions to execute code without literal <script> tags.'
    },
    {
      code: `if (templateUrl.startsWith('https://')) { const templateContent = await response.text(); }`,
      correct: false,
      explanation: 'HTTPS validation doesn\'t ensure template safety. Attackers can host malicious templates on HTTPS domains, and protocol security doesn\'t prevent content injection.'
    },
    {
      code: `const templateContent = await response.text(); if (templateContent.includes('{{')) { throw new Error('Dynamic expressions not allowed'); }`,
      correct: false,
      explanation: 'Blocking template expressions defeats the purpose of template systems. This breaks legitimate functionality while missing other injection vectors like script tags or event handlers.'
    },
    {
      code: `const templateContent = encodeURIComponent(await response.text());`,
      correct: false,
      explanation: 'URL encoding template content breaks template rendering functionality. The encoded content won\'t process correctly and doesn\'t address the fundamental trust issue with external sources.'
    },
    {
      code: `try { const templateContent = await response.text(); } catch(e) { return '<div>Safe fallback</div>'; }`,
      correct: false,
      explanation: 'Exception handling for network errors doesn\'t prevent malicious template execution. If the fetch succeeds with malicious content, it will be processed and potentially executed.'
    },
    {
      code: `const templateContent = await response.text(); if (templateType === 'ejs') { return 'EJS disabled for security'; }`,
      correct: false,
      explanation: 'Disabling EJS helps but other template engines remain vulnerable. Handlebars and Mustache can still process malicious expressions from untrusted template sources.'
    },
    {
      code: `const hash = crypto.createHash('md5').update(templateUrl).digest('hex'); const templateContent = await response.text();`,
      correct: false,
      explanation: 'Hashing the URL doesn\'t improve security. The hash has no bearing on template content safety, and malicious templates are still loaded and processed from untrusted sources.'
    }
  ]
}