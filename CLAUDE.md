# CWE Learning Platform - Development Guide

This guide contains everything learned during development of this interactive CWE learning platform.

## Project Overview

An interactive Vue TypeScript application for learning Common Weakness Enumerations (CWEs) through drag-and-drop code replacement exercises. Users identify vulnerable code lines and drag correct replacements onto them, with real-time feedback and comprehensive vulnerability intelligence from MITRE.

## Architecture

### API-Driven Design
- **MITRE CWE API Integration**: Fetches real-time vulnerability data from `https://cwe-api.mitre.org/api/v1/cwe/weakness/{id}`
- **Smart Fallback**: Graceful degradation with comprehensive static data when API unavailable (CORS issues)
- **No Static CVE Files**: All vulnerability intelligence comes from official sources

### Core Components
```
src/
├── components/CWEViewer.vue    # Main interactive component
├── services/cweAPI.ts          # MITRE API integration with fallback
├── data/exercises/             # Individual exercise definitions
└── templates/                  # Exercise generation system
```

## Creating New CWE Exercises

### 1. Use MITRE's Real Examples

**DO THIS**: Extract actual vulnerable code patterns from MITRE's demonstrative examples
```bash
# Research CWE examples
curl -s "https://cwe-api.mitre.org/api/v1/cwe/weakness/79" | jq '.demonstrative_examples'
```

**Example for CWE-79 (XSS)** - Use MITRE's actual patterns:
```typescript
// GOOD: Real MITRE examples as wrong answers
options: [
  {
    code: `echo '<div>Welcome, ' . $_GET['username'] . '</div>';`, // Direct from MITRE
    correct: false,
    explanation: 'Direct output of unsanitized GET parameter allows script injection'
  },
  {
    code: `$name = $_COOKIE["myname"]; echo "$name just logged in.";`, // MITRE example
    correct: false, 
    explanation: 'Unsanitized cookie values can contain malicious scripts'
  }
]
```

### 2. Exercise Structure Standards

**Required Fields:**
- `cweId`: Official CWE identifier (e.g., "CWE-79")
- `name`: Descriptive scenario name
- `vulnerableFunction`: Complete realistic function
- `vulnerableLine`: Specific line to replace
- `options`: 10 total (1 correct, 9 wrong from MITRE examples)

**Quality Standards:**
- **Realistic contexts**: Business logic that developers recognize
- **Progressive difficulty**: Start simple, add complexity
- **Authentic patterns**: Based on real-world vulnerabilities

### 3. Using the Template System

```bash
# Generate new exercise
cd src/templates
node generate-exercise.js CWE-79 "Cross-Site Scripting"

# Edit generated file with MITRE examples
# Add to src/data/exercises/index.ts
```

## Technical Implementation Lessons

### 1. Drag and Drop UX

**Key Learning**: Direct vulnerable line targeting works better than drop zones
```vue
<!-- GOOD: Vulnerable line as drop target -->
<span 
  class="vulnerable-line"
  @dragover.prevent="handleDragOver"
  @drop="handleDrop"
>
  {{ vulnerableLine }}
</span>

<!-- AVOID: Separate drop zones -->
<div class="drop-zone">Drop here</div>
```

### 2. Option Randomization

**Fisher-Yates Shuffle**: Ensures fair randomization of 6 options (1 correct + 5 random wrong)
```typescript
// Select 5 random wrong from 9 total wrong options
const shuffledWrong = [...wrongOptions]
for (let i = shuffledWrong.length - 1; i > 0; i--) {
  const j = Math.floor(Math.random() * (i + 1));
  [shuffledWrong[i], shuffledWrong[j]] = [shuffledWrong[j], shuffledWrong[i]]
}
```

### 3. Quote Escaping in Explanations

**Critical Bug Pattern**: SQL examples in explanation strings need proper escaping
```typescript
// WRONG: Causes compilation errors
explanation: 'Injection like "admin\' OR \'1\'=\'1" works because...'

// CORRECT: Use template literals for SQL examples
explanation: `Injection like "admin' OR '1'='1" works because...`
```

### 4. API Integration with CORS Handling

**Robust Pattern**: Try API first, fallback to comprehensive static data
```typescript
static async fetchCWE(cweId: string): Promise<CWEData> {
  try {
    const response = await fetch(`${this.baseUrl}/${cweId}`)
    if (!response.ok) throw new Error(`HTTP ${response.status}`)
    return this.transformAPIData(cweId, await response.json())
  } catch (error) {
    console.warn(`API failed for CWE-${cweId}, using fallback`)
    return this.getFallbackCWEData(cweId) // Comprehensive static data
  }
}
```

## Content Strategy

### Wrong Answer Categories

Based on MITRE examples, create diverse wrong options:

1. **Insufficient Sanitization**: Partial fixes that still fail
   ```javascript
   // Example: Case-sensitive filtering
   input.replaceAll("script", ""); // Bypassed by <SCRIPT>
   ```

2. **Wrong Escaping Context**: Right idea, wrong implementation
   ```php
   // URL encoding for HTML context
   echo htmlspecialchars($input, ENT_QUOTES, 'UTF-8'); // CORRECT
   echo urlencode($input); // WRONG CONTEXT
   ```

3. **Type Confusion**: Language-specific gotchas
   ```javascript
   parseInt(userId) // Helps but doesn't prevent all injection
   JSON.stringify(input) // Adds quotes but not comprehensive
   ```

4. **Legacy/Deprecated Methods**: Old approaches that never worked
   ```javascript
   escape(input) // JavaScript URL escaping, not for HTML
   ```

### Technical Explanations

**Format**: Brief why it's wrong + what happens
```typescript
explanation: 'URL encoding is for HTTP parameters, not HTML content. Malicious scripts like <script>alert(1)</script> remain executable in HTML context.'
```

## Development Workflow

### 1. Research Phase
- Fetch MITRE CWE data via WebFetch
- Extract demonstrative examples 
- Identify common vulnerability patterns
- Note real CVEs for context

### 2. Exercise Creation
- Use generator script for boilerplate
- Replace placeholders with MITRE examples
- Create realistic vulnerable function
- Test drag-drop interaction

### 3. Quality Assurance
- Verify compilation (watch for quote escaping)
- Test randomization works
- Confirm API fallback works
- Validate educational value

## Styling Guidelines

### Visual Hierarchy
- **Vulnerable lines**: Yellow highlight (attention grabbing)
- **Correct answers**: Green background (success state)
- **Wrong answers**: Red explanations (error state)
- **Drag states**: Blue highlights (interactive feedback)

### Responsive Design
- **Desktop**: Side-by-side CVE and explanation layout
- **Mobile**: Stacked layout with appropriate spacing
- **Touch targets**: Adequate size for drag interactions

## Future CWE Priorities

Based on OWASP Top 10 and MITRE data:

1. **CWE-79**: Cross-Site Scripting (rich MITRE examples available)
   - **Example created**: `src/data/exercises/cwe-79-example.ts` demonstrates the MITRE pattern approach
2. **CWE-22**: Path Traversal (directory manipulation patterns)  
3. **CWE-78**: OS Command Injection (system call vulnerabilities)
4. **CWE-502**: Deserialization (object manipulation attacks)

## API Data Structure

### CWE API Response Transformation
```typescript
interface CWEData {
  id: string                 // "CWE-89"
  name: string              // "SQL Injection"  
  severity: string          // "High"
  likelihood: string        // "High"
  relatedCVEs: string[]     // ["CVE-2024-6847", ...]
  attackVectors: string[]   // Real attack techniques
  mitigation: string[]      // Proven defenses
  detectMethods: string[]   // Detection approaches
}
```

## Performance Considerations

- **API Caching**: Browser caches API responses for 5 minutes
- **Lazy Loading**: CWE data fetched only when exercise loads
- **Error Boundaries**: Graceful degradation if API fails
- **Bundle Size**: Tree-shaking eliminates unused dependencies

## Security Notes

This is an educational platform teaching about vulnerabilities. The vulnerable code examples are:
- **Isolated**: Run in browser context only, no server execution
- **Educational**: Demonstrate patterns, not provide exploitation tools
- **Contextual**: Always paired with secure alternatives
- **Sourced**: Based on official MITRE documentation

## Deployment

### Development
```bash
npm install
npm run dev  # http://localhost:5173
```

### Production
```bash
npm run build
# Deploy dist/ directory to static hosting
```

### Environment Variables
None required - API calls are direct to MITRE public endpoints.

---

**Last Updated**: When project switched to MITRE API integration
**Maintainer**: Development team
**License**: Educational use