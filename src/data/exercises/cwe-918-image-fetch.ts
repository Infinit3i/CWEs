import type { Exercise } from '@/data/exercises'

/**
 * CWE-918: Server-Side Request Forgery in Image Processing Service
 * Enterprise scenario: Content management system fetching external images
 */
export const cwe918ImageFetch: Exercise = {
  cweId: 'CWE-918',
  name: 'Server-Side Request Forgery - Image Fetcher',

  vulnerableFunction: `class ImageProcessingService {
  async fetchAndProcessImage(imageUrl: string, userId: string) {
    console.log(\`User \${userId} requesting image: \${imageUrl}\`);

    const response = await fetch(imageUrl, {
      headers: {
        'User-Agent': 'ImageProcessor/2.0',
        'Accept': 'image/*'
      },
      timeout: 10000
    });

    if (!response.ok) {
      throw new Error(\`Failed to fetch image: \${response.status}\`);
    }

    const contentType = response.headers.get('content-type');
    if (!contentType?.startsWith('image/')) {
      throw new Error('Response is not an image');
    }

    const imageBuffer = await response.arrayBuffer();
    return await this.processImage(imageBuffer);
  }
}`,

  vulnerableLine: `const response = await fetch(imageUrl, {`,

  options: [
    {
      code: `this.validateImageUrl(imageUrl); const response = await fetch(imageUrl, {`,
      correct: true,
      explanation: `Correct! URL validation should check against allowlisted image hosting domains and reject internal/private network addresses. This prevents SSRF while allowing legitimate external image processing.`
    },
    {
      code: `const response = await fetch(imageUrl, {`,
      correct: false,
      explanation: 'From MITRE: Direct user input to fetch() enables SSRF. Attackers can target internal services, cloud metadata endpoints, or file:// protocols through image URL parameters.'
    },
    {
      code: `if (!imageUrl.match(/\\.(jpg|png|gif|webp)$/i)) throw new Error('Invalid image extension'); const response = await fetch(imageUrl, {`,
      correct: false,
      explanation: 'File extension validation does not prevent SSRF. URLs targeting internal services can include image extensions or use query parameters to bypass extension checks.'
    },
    {
      code: `const url = new URL(imageUrl); if (url.protocol !== 'https:') throw new Error('Only HTTPS images allowed'); const response = await fetch(imageUrl, {`,
      correct: false,
      explanation: 'Protocol validation alone is insufficient. HTTPS URLs can still target internal HTTPS services, cloud metadata over HTTPS, or other sensitive endpoints.'
    },
    {
      code: `if (imageUrl.toLowerCase().includes('localhost')) throw new Error('Localhost not allowed'); const response = await fetch(imageUrl, {`,
      correct: false,
      explanation: 'Case-insensitive string filtering is easily bypassed with IP addresses (127.0.0.1), IPv6 (::1), or alternative localhost representations.'
    },
    {
      code: `const domain = new URL(imageUrl).hostname; if (domain.startsWith('192.168.') || domain.startsWith('10.')) throw new Error('Private networks blocked');`,
      correct: false,
      explanation: 'Partial private network filtering misses many internal ranges (172.16-31.x, 169.254.x, IPv6 ranges) and cloud metadata endpoints.'
    },
    {
      code: `if (imageUrl.length > 200) throw new Error('Image URL too long'); const response = await fetch(imageUrl, {`,
      correct: false,
      explanation: 'Length validation does not prevent SSRF attacks. Short URLs can still target sensitive internal resources and metadata endpoints.'
    },
    {
      code: `const parsed = new URL(imageUrl); if (parsed.port && parsed.port !== '80' && parsed.port !== '443') throw new Error('Non-standard ports blocked');`,
      correct: false,
      explanation: 'Port filtering allows standard HTTP/HTTPS ports where many internal services run, including cloud metadata services on port 80.'
    }
  ]
}