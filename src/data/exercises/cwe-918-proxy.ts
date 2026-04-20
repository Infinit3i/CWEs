import type { Exercise } from '@/data/exercises'

/**
 * CWE-918: Server-Side Request Forgery in API Proxy Service
 * Infrastructure scenario: API gateway forwarding requests to backend services
 */
export const cwe918Proxy: Exercise = {
  cweId: 'CWE-918',
  name: 'Server-Side Request Forgery - API Proxy Gateway',

  vulnerableFunction: `class ApiProxyService {
  async forwardRequest(targetUrl: string, headers: Record<string, string>, body?: string) {
    const requestOptions = {
      method: headers['x-forwarded-method'] || 'GET',
      headers: {
        'User-Agent': 'ApiProxy/1.0',
        'Authorization': headers.authorization,
        'Content-Type': headers['content-type']
      },
      body: body
    };

    console.log(\`Forwarding request to: \${targetUrl}\`);

    const response = await fetch(targetUrl, requestOptions);

    return {
      status: response.status,
      headers: Object.fromEntries(response.headers.entries()),
      body: await response.text()
    };
  }
}`,

  vulnerableLine: `const response = await fetch(targetUrl, requestOptions);`,

  options: [
    {
      code: `const allowedHosts = ['api.partner.com', 'service.trusted.net']; const url = new URL(targetUrl); if (!allowedHosts.includes(url.hostname)) throw new Error('Host not allowed'); const response = await fetch(targetUrl, requestOptions);`,
      correct: true,
      explanation: `Correct! Allowlisting specific trusted hostnames prevents SSRF by ensuring requests only reach pre-approved backend services. This blocks access to internal infrastructure and metadata endpoints.`
    },
    {
      code: `const response = await fetch(targetUrl, requestOptions);`,
      correct: false,
      explanation: 'From MITRE: Unvalidated URL forwarding enables SSRF attacks. Attackers can access internal services, cloud metadata (http://169.254.169.254/), or localhost services through the proxy.'
    },
    {
      code: `if (targetUrl.includes('localhost') || targetUrl.includes('127.0.0.1')) throw new Error('Local access denied'); const response = await fetch(targetUrl, requestOptions);`,
      correct: false,
      explanation: 'String-based blacklisting is insufficient. Attackers bypass with alternative localhost representations: 0.0.0.0, [::1], 127.1, or decimal IP encoding.'
    },
    {
      code: `const url = new URL(targetUrl); if (url.hostname.endsWith('.internal')) throw new Error('Internal domains blocked'); const response = await fetch(targetUrl, requestOptions);`,
      correct: false,
      explanation: 'Domain suffix filtering can be bypassed with IP addresses, alternative internal domains, or cloud metadata endpoints that do not match the filter pattern.'
    },
    {
      code: `if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) throw new Error('Invalid protocol'); const response = await fetch(targetUrl, requestOptions);`,
      correct: false,
      explanation: 'Protocol validation alone is insufficient. HTTP/HTTPS URLs can still target internal infrastructure, file systems, or other sensitive internal resources.'
    },
    {
      code: `const sanitized = targetUrl.replace(/[<>'"]/g, ''); const response = await fetch(sanitized, requestOptions);`,
      correct: false,
      explanation: 'Character filtering does not prevent SSRF. Valid URLs targeting internal services do not require special characters that would be filtered.'
    },
    {
      code: `if (targetUrl.split('.').length < 2) throw new Error('Invalid domain format'); const response = await fetch(targetUrl, requestOptions);`,
      correct: false,
      explanation: 'Domain format validation does not prevent SSRF. IP addresses and properly formatted internal domains can still be targeted.'
    },
    {
      code: `const encoded = encodeURIComponent(targetUrl); const response = await fetch(encoded, requestOptions);`,
      correct: false,
      explanation: 'URL encoding the entire target URL breaks legitimate requests and does not prevent SSRF when the encoded URL is still processed.'
    }
  ]
}