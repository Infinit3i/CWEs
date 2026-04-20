import type { Exercise } from '@/data/exercises'

/**
 * CWE-918: Server-Side Request Forgery in Webhook Handler
 * Enterprise scenario: Microservice processing external webhook callbacks
 */
export const cwe918Webhook: Exercise = {
  cweId: 'CWE-918',
  name: 'Server-Side Request Forgery - Webhook Processor',

  vulnerableFunction: `class WebhookService {
  async processWebhook(callbackUrl: string, payload: any) {
    console.log(\`Processing webhook callback to: \${callbackUrl}\`);

    try {
      const response = await fetch(callbackUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        timeout: 5000
      });

      if (!response.ok) {
        throw new Error(\`Webhook failed with status: \${response.status}\`);
      }

      return await response.text();
    } catch (error) {
      console.error('Webhook delivery failed:', error.message);
      throw error;
    }
  }
}`,

  vulnerableLine: `const response = await fetch(callbackUrl, {`,

  options: [
    {
      code: `if (!this.isValidWebhookUrl(callbackUrl)) throw new Error('Invalid webhook URL'); const response = await fetch(callbackUrl, {`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    {
      code: `const response = await fetch(callbackUrl, {`,
      correct: false,
      explanation: 'Direct user input to URL parameters enables SSRF. Attackers can target internal services like http://169.254.169.254/latest/meta-data/ for cloud metadata access.'
    },
    {
      code: `const url = new URL(callbackUrl); if (url.hostname === 'localhost') throw new Error('Invalid host'); const response = await fetch(callbackUrl, {`,
      correct: false,
      explanation: 'Blacklisting specific hostnames is insufficient. Attackers can bypass with 127.0.0.1, [::1], or other localhost representations.'
    },
    {
      code: `const response = await fetch(callbackUrl.replace(/localhost|127\.0\.0\.1/gi, ''), {`,
      correct: false,
      explanation: 'String replacement filtering is easily bypassed with alternative representations like 0.0.0.0, [::1], or obfuscated IP encodings.'
    },
    {
      code: `if (!callbackUrl.startsWith('https://')) throw new Error('Only HTTPS allowed'); const response = await fetch(callbackUrl, {`,
      correct: false,
      explanation: 'Protocol validation alone is insufficient. HTTPS URLs can still target internal services, cloud metadata endpoints, or other internal infrastructure.'
    },
    {
      code: `const parsedUrl = new URL(callbackUrl); if (parsedUrl.port && parseInt(parsedUrl.port) < 1024) throw new Error('Privileged ports not allowed');`,
      correct: false,
      explanation: 'Port restrictions alone do not prevent SSRF. Internal services often run on high ports, and cloud metadata services typically use standard HTTP ports.'
    },
    {
      code: `const domain = callbackUrl.split('/')[2]; if (domain.includes('.internal')) throw new Error('Internal domains blocked');`,
      correct: false,
      explanation: 'Simple domain filtering can be bypassed with IP addresses, alternative TLDs, or subdomain variations that do not match the filtering pattern.'
    },
    {
      code: `if (callbackUrl.length > 100) throw new Error('URL too long'); const response = await fetch(callbackUrl, {`,
      correct: false,
      explanation: 'Length validation does not prevent SSRF attacks. Short URLs like http://169.254.169.254/ can access sensitive internal resources.'
    }
  ]
}