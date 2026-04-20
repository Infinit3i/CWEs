import type { Exercise } from '@/data/exercises'

/**
 * CWE-22 exercise - Template File Include
 * Based on MITRE demonstrative examples for path traversal in template systems
 */
export const cwe22TemplateInclude: Exercise = {
  cweId: 'CWE-22',
  name: 'Path Traversal - Template File Include',

  vulnerableFunction: `function renderTemplate(templateName, data) {
  const templatePath = './templates/' + templateName + '.hbs';

  if (fs.existsSync(templatePath)) {
    const templateContent = fs.readFileSync(templatePath, 'utf8');
    return Handlebars.compile(templateContent)(data);
  }
  throw new Error('Template not found');
}`,

  vulnerableLine: `const templatePath = './templates/' + templateName + '.hbs';`,

  options: [
    {
      code: `const allowedTemplates = ['header', 'footer', 'main', 'sidebar']; if (!allowedTemplates.includes(templateName)) throw new Error('Invalid template'); const templatePath = './templates/' + templateName + '.hbs';`,
      correct: true,
      explanation: `Correct! Using a whitelist of allowed template names completely prevents path traversal by only accepting predefined values. This approach eliminates any possibility of directory escape regardless of the input format.`
    },
    {
      code: `const templatePath = './templates/' + templateName + '.hbs';`,
      correct: false,
      explanation: 'Direct from MITRE: String concatenation with user input allows attackers to inject "../../../etc/passwd%00" to escape the template directory and access any file on the system.'
    },
    {
      code: `const cleaned = templateName.replace('../', ''); const templatePath = './templates/' + cleaned + '.hbs';`,
      correct: false,
      explanation: 'MITRE vulnerability: Removing only the first instance of "../" fails with nested attacks like "../../../etc/passwd" where multiple traversal sequences remain after filtering.'
    },
    {
      code: `if (templateName.startsWith('tpl_')) { const templatePath = './templates/' + templateName + '.hbs'; }`,
      correct: false,
      explanation: 'MITRE pattern: Prefix validation can be bypassed with inputs like "tpl_../../../etc/passwd" that start correctly but contain traversal sequences.'
    },
    {
      code: `const templatePath = path.resolve('./templates/', templateName + '.hbs');`,
      correct: false,
      explanation: 'Path resolution without boundary validation still allows escape. Attackers can use "../../etc/passwd" to resolve outside the templates directory.'
    },
    {
      code: `const filtered = templateName.replace(/\.\./g, '.'); const templatePath = './templates/' + filtered + '.hbs';`,
      correct: false,
      explanation: 'Replacing ".." with "." creates new vulnerabilities and may not prevent encoded traversal sequences like "%2e%2e" from working.'
    },
    {
      code: `if (templateName.includes('.')) { throw new Error('Invalid'); } const templatePath = './templates/' + templateName + '.hbs';`,
      correct: false,
      explanation: 'Blocking dots prevents some attacks but allows other traversal methods and may break legitimate template names that contain dots.'
    },
    {
      code: `const encoded = encodeURIComponent(templateName); const templatePath = './templates/' + encoded + '.hbs';`,
      correct: false,
      explanation: 'URL encoding the filename after validation does not prevent traversal sequences that were already present in the original input.'
    },
    {
      code: `const uppercase = templateName.toUpperCase(); const templatePath = './templates/' + uppercase + '.hbs';`,
      correct: false,
      explanation: 'Case conversion does not prevent path traversal. Uppercase "../../../ETC/PASSWD" sequences remain effective on case-insensitive systems.'
    },
    {
      code: `if (templateName.match(/^[a-z]+$/)) { const templatePath = './templates/' + templateName + '.hbs'; }`,
      correct: false,
      explanation: 'While this regex is restrictive, it may be too limiting for legitimate template names and should be combined with a whitelist approach for better usability.'
    }
  ]
}