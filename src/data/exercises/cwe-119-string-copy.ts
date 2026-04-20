import type { Exercise } from '@/data/exercises'

/**
 * CWE-119 exercise: String copy buffer overflow
 * Based on unsafe string operations that exceed buffer boundaries
 */
export const cwe119StringCopy: Exercise = {
  cweId: 'CWE-119',
  name: 'Memory Buffer Bounds - User Input String Copy Operations',

  vulnerableFunction: `function processUserInput(userInput, category) {
  const MAX_CATEGORY_LENGTH = 32;
  const MAX_INPUT_LENGTH = 256;

  // Validate input length
  if (userInput.length > MAX_INPUT_LENGTH) {
    throw new Error('Input too long');
  }

  // Create fixed-size buffer for processed data
  const processedData = {
    category: new Array(MAX_CATEGORY_LENGTH),
    content: new Array(MAX_INPUT_LENGTH),
    metadata: new Array(64)
  };

  // Copy category (could be longer than buffer)
  for (let i = 0; i < category.length; i++) {
    processedData.category[i] = category[i];
  }

  // Copy user input
  for (let i = 0; i < userInput.length; i++) {
    processedData.content[i] = userInput[i];
  }

  // Generate metadata (timestamp + category + content length)
  const timestamp = Date.now().toString();
  const metadata = timestamp + '|' + category + '|' + userInput.length;

  for (let i = 0; i < metadata.length; i++) {
    processedData.metadata[i] = metadata[i];
  }

  return {
    category: processedData.category.join('').replace(/\\0/g, ''),
    content: processedData.content.join('').replace(/\\0/g, ''),
    metadata: processedData.metadata.join('').replace(/\\0/g, '')
  };
}`,

  vulnerableLine: `for (let i = 0; i < category.length; i++) {`,

  options: [
    {
      code: `function processUserInput(userInput, category) {
  const MAX_CATEGORY_LENGTH = 32;
  const MAX_INPUT_LENGTH = 256;
  const MAX_METADATA_LENGTH = 64;

  // Validate all input lengths
  if (userInput.length > MAX_INPUT_LENGTH) {
    throw new Error('Input too long');
  }

  if (category.length > MAX_CATEGORY_LENGTH) {
    throw new Error('Category name too long');
  }

  // Generate metadata first to validate length
  const timestamp = Date.now().toString();
  const metadata = timestamp + '|' + category + '|' + userInput.length;

  if (metadata.length > MAX_METADATA_LENGTH) {
    throw new Error('Metadata too long');
  }

  // Safe copying with validated lengths
  const processedData = {
    category: category,  // Use string directly
    content: userInput,  // Use string directly
    metadata: metadata   // Use string directly
  };

  return processedData;
}`,
      correct: true,
      explanation: `Correct! Pre-validation of all string lengths prevents buffer overflow. By checking bounds before any copy operations and using strings directly instead of fixed-size character arrays, all buffer overflows are prevented.`
    },
    // String copy buffer overflow vulnerabilities
    {
      code: `for (let i = 0; i < category.length; i++) {
    processedData.category[i] = category[i];
}`,
      correct: false,
      explanation: 'Unchecked string copy allows buffer overflow. Category names longer than 32 characters will overwrite adjacent memory in the processedData structure, corrupting other fields.'
    },
    {
      code: `const metadata = timestamp + '|' + category + '|' + userInput.length;
for (let i = 0; i < metadata.length; i++) {
    processedData.metadata[i] = metadata[i];
}`,
      correct: false,
      explanation: 'Metadata string construction without length validation. Long timestamps, categories, or the combined string can exceed the 64-character metadata buffer, causing overflow.'
    },
    {
      code: `if (category.length <= MAX_CATEGORY_LENGTH) {
    for (let i = 0; i < category.length; i++) {
        processedData.category[i] = category[i];
    }
}`,
      correct: false,
      explanation: 'Silent truncation through conditional copying can create incomplete data. Applications may not realize the category was truncated, leading to logic errors or data corruption.'
    },
    {
      code: `const safeCategoryLength = Math.min(category.length, MAX_CATEGORY_LENGTH);
for (let i = 0; i < safeCategoryLength; i++) {
    processedData.category[i] = category[i];
}`,
      correct: false,
      explanation: 'Silent truncation with Math.min masks data loss. While preventing overflow, truncated categories may become invalid or indistinguishable, corrupting application logic.'
    },
    {
      code: `try {
    for (let i = 0; i < category.length; i++) {
        processedData.category[i] = category[i];
    }
} catch (e) {
    console.log('Category copy failed');
}`,
      correct: false,
      explanation: 'JavaScript arrays automatically expand rather than throwing exceptions on out-of-bounds writes. Try-catch will not detect buffer overflow conditions in JavaScript arrays.'
    },
    {
      code: `for (let i = 0; i < category.length && i < MAX_CATEGORY_LENGTH; i++) {
    processedData.category[i] = category[i];
}
// Continue without error if truncated`,
      correct: false,
      explanation: 'Loop bounds limiting with silent truncation can corrupt application state. The category may be partially copied, creating invalid or ambiguous category values.'
    },
    {
      code: `const categoryBuffer = new Array(MAX_CATEGORY_LENGTH);
category.split('').forEach((char, index) => {
    categoryBuffer[index] = char;
});`,
      correct: false,
      explanation: 'forEach without bounds checking allows buffer overflow. The callback function will write beyond array boundaries if the category exceeds the buffer size.'
    },
    {
      code: `let writePos = 0;
for (const char of category) {
    if (writePos < MAX_CATEGORY_LENGTH) {
        processedData.category[writePos++] = char;
    }
}`,
      correct: false,
      explanation: 'Per-character bounds checking creates silent truncation. While preventing overflow, the truncated result may be invalid or misleading to application logic.'
    },
    {
      code: `const encodedCategory = btoa(category);
if (encodedCategory.length <= MAX_CATEGORY_LENGTH) {
    for (let i = 0; i < encodedCategory.length; i++) {
        processedData.category[i] = encodedCategory[i];
    }
}`,
      correct: false,
      explanation: 'Base64 encoding changes data representation and may not fit application requirements. Encoded strings are also longer than originals, reducing effective buffer capacity.'
    },
    {
      code: `const chunkSize = Math.floor(MAX_CATEGORY_LENGTH / category.length);
for (let i = 0; i < MAX_CATEGORY_LENGTH; i++) {
    const sourceIndex = Math.floor(i / chunkSize);
    processedData.category[i] = category[sourceIndex] || '';
}`,
      correct: false,
      explanation: 'Character sampling/stretching corrupts string content. This approach creates invalid strings that do not represent the original category data.'
    }
  ]
}