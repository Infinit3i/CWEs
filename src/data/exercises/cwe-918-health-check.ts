import type { Exercise } from '@/data/exercises'

/**
 * CWE-918: Server-Side Request Forgery in Service Health Monitor
 * DevOps scenario: Monitoring service checking external endpoint availability
 */
export const cwe918HealthCheck: Exercise = {
  cweId: 'CWE-918',
  name: 'Server-Side Request Forgery - Health Check Monitor',

  vulnerableFunction: `class ServiceHealthMonitor {
  async checkEndpointHealth(serviceUrl: string, serviceName: string) {
    console.log(\`Checking health for \${serviceName}: \${serviceUrl}\`);

    const startTime = Date.now();

    try {
      const response = await fetch(serviceUrl + '/health', {
        method: 'GET',
        headers: {
          'User-Agent': 'HealthMonitor/1.0',
          'Accept': 'application/json'
        },
        timeout: 5000
      });

      const responseTime = Date.now() - startTime;
      const status = response.status;
      const body = await response.text();

      return {
        serviceName,
        url: serviceUrl,
        status,
        responseTime,
        healthy: status === 200,
        body: body.substring(0, 100)  // First 100 chars
      };
    } catch (error) {
      return {
        serviceName,
        url: serviceUrl,
        status: 0,
        responseTime: Date.now() - startTime,
        healthy: false,
        error: error.message
      };
    }
  }
}`,

  vulnerableLine: `const response = await fetch(serviceUrl + '/health', {`,

  options: [
    {
      code: `if (!this.isAllowedService(serviceUrl)) throw new Error('Service not in monitoring allowlist'); const response = await fetch(serviceUrl + '/health', {`,
      correct: true,
      explanation: `Correct! Health monitoring should only check pre-registered, trusted services from a configured allowlist. This prevents SSRF while enabling legitimate service monitoring functionality.`
    },
    {
      code: `const response = await fetch(serviceUrl + '/health', {`,
      correct: false,
      explanation: 'From MITRE: User-controlled URLs in monitoring systems enable SSRF. Attackers can probe internal infrastructure, cloud metadata endpoints, or sensitive services through health checks.'
    },
    {
      code: `if (!serviceUrl.includes('.')) throw new Error('Invalid service URL format'); const response = await fetch(serviceUrl + '/health', {`,
      correct: false,
      explanation: 'Requiring dots in URLs does not prevent SSRF. IP addresses contain dots, and hostnames can be constructed to bypass this simple check.'
    },
    {
      code: `const url = new URL(serviceUrl); if (url.port && url.port === '22') throw new Error('SSH port blocked'); const response = await fetch(serviceUrl + '/health', {`,
      correct: false,
      explanation: 'Blocking only SSH port (22) leaves all other internal services exposed. HTTP services on ports 80, 443, 8080, etc. remain accessible.'
    },
    {
      code: `if (serviceUrl.toLowerCase().includes('admin')) throw new Error('Admin endpoints blocked'); const response = await fetch(serviceUrl + '/health', {`,
      correct: false,
      explanation: 'Keyword filtering is easily bypassed with alternative paths, IP addresses, or services that do not contain blocked keywords but are still sensitive.'
    },
    {
      code: `const parsed = new URL(serviceUrl); if (!parsed.hostname.endsWith('.com')) throw new Error('Only .com domains allowed'); const response = await fetch(serviceUrl + '/health', {`,
      correct: false,
      explanation: 'TLD filtering allows internal .com services and misses legitimate services on other TLDs. Attackers can also use IP addresses to bypass domain filtering.'
    },
    {
      code: `if (serviceUrl.includes('localhost') || serviceUrl.includes('127.')) throw new Error('Local services blocked'); const response = await fetch(serviceUrl + '/health', {`,
      correct: false,
      explanation: 'Partial localhost filtering misses many internal representations: 0.0.0.0, [::1], 127.0.0.1 (exact match), private networks, and cloud metadata endpoints.'
    },
    {
      code: `const timeout = serviceUrl.includes('external') ? 5000 : 1000; const response = await fetch(serviceUrl + '/health', { timeout });`,
      correct: false,
      explanation: 'Different timeouts based on URL content do not prevent SSRF attacks. Internal services can still be probed regardless of timeout values.'
    }
  ]
}