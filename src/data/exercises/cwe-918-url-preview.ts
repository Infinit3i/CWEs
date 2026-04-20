import type { Exercise } from '@/data/exercises'

/**
 * CWE-918: Server-Side Request Forgery in URL Preview Generator
 * Enterprise scenario: Social media platform generating link previews
 */
export const cwe918UrlPreview: Exercise = {
  cweId: 'CWE-918',
  name: 'Server-Side Request Forgery - URL Preview Service',

  vulnerableFunction: `class UrlPreviewService {
  async generatePreview(url: string) {
    console.log(\`Generating preview for: \${url}\`);

    const response = await fetch(url, {
      method: 'GET',
      headers: {
        'User-Agent': 'SocialBot/1.0 (+https://company.com/bot)',
        'Accept': 'text/html,application/xhtml+xml'
      },
      follow: 5,  // Follow up to 5 redirects
      timeout: 15000
    });

    const html = await response.text();
    const title = this.extractTitle(html);
    const description = this.extractDescription(html);
    const image = this.extractOpenGraphImage(html);

    return {
      title,
      description,
      image,
      url: response.url  // Final URL after redirects
    };
  }
}`,

  vulnerableLine: `const response = await fetch(url, {`,

  options: [
    {
      code: `await this.validateExternalUrl(url); const response = await fetch(url, {`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    {
      code: `const response = await fetch(url, {`,
      correct: false,
      explanation: 'Unvalidated URL fetching with redirect following enables SSRF. Attackers can access internal services, cloud metadata APIs, or use redirects to bypass simple filters.'
    },
    {
      code: `if (!url.startsWith('http://') && !url.startsWith('https://')) throw new Error('Invalid protocol'); const response = await fetch(url, {`,
      correct: false,
      explanation: 'Protocol filtering alone allows SSRF through HTTP/HTTPS URLs targeting internal infrastructure, localhost services, and cloud metadata endpoints.'
    },
    {
      code: `const domain = new URL(url).hostname; if (domain === 'localhost' || domain === '127.0.0.1') throw new Error('Local access denied'); const response = await fetch(url, {`,
      correct: false,
      explanation: 'Exact hostname matching misses many localhost alternatives: 0.0.0.0, [::1], 127.1, private network ranges, and cloud metadata endpoints.'
    },
    {
      code: `if (url.includes('169.254.169.254')) throw new Error('Metadata endpoint blocked'); const response = await fetch(url, {`,
      correct: false,
      explanation: 'Blocking only AWS metadata endpoint misses other cloud providers (Azure: 169.254.169.254:80/metadata, GCP: metadata.google.internal) and all other internal services.'
    },
    {
      code: `const sanitized = url.replace(/[<>'"{}]/g, ''); const response = await fetch(sanitized, {`,
      correct: false,
      explanation: 'Character filtering does not prevent SSRF attacks. Valid internal URLs do not require special characters that would be filtered.'
    },
    {
      code: `if (url.length < 10) throw new Error('URL too short'); const response = await fetch(url, {`,
      correct: false,
      explanation: 'Length validation is insufficient for SSRF prevention. Short URLs like http://0.0.0.0/ can still target internal services.'
    },
    {
      code: `const parsed = new URL(url); if (parsed.pathname.includes('..')) throw new Error('Path traversal detected'); const response = await fetch(url, {`,
      correct: false,
      explanation: 'Path traversal filtering addresses different vulnerabilities but does not prevent SSRF attacks against internal services or metadata endpoints.'
    }
  ]
}