import type { Exercise } from '@/data/exercises'

/**
 * CWE-190 exercise: Memory allocation integer overflow
 * Based on MITRE demonstrative examples showing buffer allocation vulnerabilities
 */
export const cwe190MemoryAllocation: Exercise = {
  cweId: 'CWE-190',
  name: 'Integer Overflow - Memory Allocation for Image Processing',

  vulnerableFunction: `function processImageBatch(imageCount, pixelsPerImage) {
  if (imageCount <= 0 || pixelsPerImage <= 0) {
    throw new Error('Invalid parameters');
  }

  // Allocate buffer for all image data
  const totalPixels = imageCount * pixelsPerImage;
  const buffer = new ArrayBuffer(totalPixels * 4); // 4 bytes per pixel (RGBA)

  console.log(\`Allocated buffer for \${totalPixels} pixels\`);
  return new Uint8Array(buffer);
}

// Example call that could overflow:
// processImageBatch(1000000, 5000); // 5 billion pixels`,

  vulnerableLine: `const totalPixels = imageCount * pixelsPerImage;`,

  options: [
    {
      code: `function processImageBatch(imageCount, pixelsPerImage) {
  const MAX_PIXELS = Number.MAX_SAFE_INTEGER / 4;
  if (imageCount <= 0 || pixelsPerImage <= 0) {
    throw new Error('Invalid parameters');
  }
  if (imageCount > MAX_PIXELS / pixelsPerImage) {
    throw new Error('Image batch too large - would cause overflow');
  }
  const totalPixels = imageCount * pixelsPerImage;
  return new Uint8Array(totalPixels * 4);
}`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    // Real MITRE demonstrative examples as wrong answers
    {
      code: `const totalPixels = imageCount * pixelsPerImage;
const buffer = new ArrayBuffer(totalPixels * 4);`,
      correct: false,
      explanation: 'Unchecked multiplication can overflow. With imageCount=1073741824 and pixelsPerImage=4, the result wraps to 0, allocating a tiny buffer instead of the intended size.'
    },
    {
      code: `if (imageCount < 1000000 && pixelsPerImage < 1000000) {
    const totalPixels = imageCount * pixelsPerImage;
    return new ArrayBuffer(totalPixels * 4);
}`,
      correct: false,
      explanation: 'MITRE-style insufficient bounds checking. Even with individual limits, 999999 * 999999 = 999998000001, which can still overflow when multiplied by 4 bytes.'
    },
    {
      code: `const totalPixels = Math.min(imageCount * pixelsPerImage, 2147483647);
return new ArrayBuffer(totalPixels * 4);`,
      correct: false,
      explanation: 'Clamping the result after overflow has occurred. The multiplication may have already wrapped around before the Math.min is applied.'
    },
    {
      code: `if (imageCount > 0 && pixelsPerImage > 0) {
    const totalPixels = imageCount * pixelsPerImage;
    return totalPixels > 0 ? new ArrayBuffer(totalPixels * 4) : null;
}`,
      correct: false,
      explanation: 'Checking positivity after multiplication is too late. Overflow can produce negative results or wrap to small positive values, both bypassing this check.'
    },
    {
      code: `const safeCount = imageCount & 0x7FFFFFFF;
const safePixels = pixelsPerImage & 0x7FFFFFFF;
return new ArrayBuffer(safeCount * safePixels * 4);`,
      correct: false,
      explanation: 'Bit masking to force positive values does not prevent overflow in the multiplication. Large values can still overflow after masking.'
    },
    {
      code: `try {
    const totalPixels = imageCount * pixelsPerImage;
    return new ArrayBuffer(totalPixels * 4);
} catch (e) {
    return new ArrayBuffer(1024); // Fallback
}`,
      correct: false,
      explanation: 'JavaScript integer overflow does not throw exceptions - it silently wraps around. The try-catch will not detect the overflow condition.'
    },
    {
      code: `const totalPixels = parseInt(imageCount.toString()) * parseInt(pixelsPerImage.toString());
return new ArrayBuffer(totalPixels * 4);`,
      correct: false,
      explanation: 'String conversion and parsing does not prevent integer overflow. The multiplication still occurs with the same values and same overflow risk.'
    },
    {
      code: `if (String(imageCount * pixelsPerImage).length < 10) {
    return new ArrayBuffer(imageCount * pixelsPerImage * 4);
}`,
      correct: false,
      explanation: 'String length checking after multiplication has already occurred. Overflow values may have wrapped to small numbers with short string representations.'
    },
    {
      code: `const totalPixels = (imageCount + pixelsPerImage) * Math.min(imageCount, pixelsPerImage);
return new ArrayBuffer(totalPixels * 4);`,
      correct: false,
      explanation: 'Alternative calculation methods can still overflow. This formula can produce large intermediate results that exceed safe integer bounds.'
    }
  ]
}