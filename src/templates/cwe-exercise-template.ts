import type { Exercise } from '@/data/exercises'

/**
 * Template for creating new CWE exercises
 *
 * Instructions:
 * 1. Research MITRE examples: curl -s "https://cwe-api.mitre.org/api/v1/cwe/weakness/[CWE-ID]"
 * 2. Extract demonstrative_examples from API response for wrong answer options
 * 3. Copy this template to /src/data/exercises/
 * 4. Replace all [PLACEHOLDER] values with real MITRE patterns
 * 5. Import in /src/data/exercises/index.ts
 *
 * IMPORTANT: Use MITRE's actual vulnerable code examples as wrong answers.
 * This ensures authenticity and educational value.
 *
 * Note: CWE data (severity, CVEs, mitigation) fetched automatically from MITRE API.
 */

export const cweTemplate: Exercise = {
  cweId: '[CWE-XXX]',
  name: '[CWE Type] - [Scenario Description]',

  vulnerableFunction: `function [functionName]([parameters]) {
  // Replace with realistic business logic context
  const [operation] = "[VULNERABLE CODE PATTERN]";
  return [result];
}`,

  vulnerableLine: `const [operation] = "[SPECIFIC LINE TO REPLACE]";`,

  options: [
    {
      code: `const [operation] = "[SECURE SOLUTION - parameterized/escaped/validated]";`,
      correct: true,
      explanation: `Correct! [Technical explanation of why this prevents the vulnerability]`
    },
    // IMPORTANT: Use MITRE's demonstrative_examples for wrong answers
    {
      code: `[MITRE EXAMPLE 1 - direct from demonstrative_examples]`,
      correct: false,
      explanation: '[Explain specific vulnerability in this MITRE pattern]'
    },
    {
      code: `[MITRE EXAMPLE 2 - another demonstrative pattern]`,
      correct: false,
      explanation: '[Why this real-world pattern fails]'
    },
    {
      code: `const query = "[WRONG APPROACH 2]";`,
      correct: false,
      explanation: '[Explain why this approach is still vulnerable]'
    },
    {
      code: `[MITRE EXAMPLE 3 - flawed defense pattern]`,
      correct: false,
      explanation: '[Why this common "fix" still fails - reference MITRE explanation]'
    },
    {
      code: `[INSUFFICIENT_FILTERING - case sensitive filtering example]`,
      correct: false,
      explanation: '[Explain bypass technique from MITRE examples]'
    },
    {
      code: `[WRONG_CONTEXT - right idea, wrong implementation]`,
      correct: false,
      explanation: '[Context-specific vulnerability explanation]'
    },
    {
      code: `[TYPE_CONFUSION - language-specific gotcha]`,
      correct: false,
      explanation: '[Type-based vulnerability from MITRE patterns]'
    },
    {
      code: `[LEGACY_METHOD - deprecated/dangerous function]`,
      correct: false,
      explanation: '[Why this old approach never worked securely]'
    },
    {
      code: `[PARTIAL_SANITIZATION - incomplete protection]`,
      correct: false,
      explanation: '[How this partial fix can be bypassed]'
    },
    {
      code: `[ENCODING_MISMATCH - wrong encoding for context]`,
      correct: false,
      explanation: '[Context-specific encoding failure]'
    }
  ]
  // CWE data (severity, CVEs, attack vectors, mitigation) is automatically
  // fetched from the MITRE CWE API when the exercise loads
}