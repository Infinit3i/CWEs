# Exercise Templates

This directory contains templates and tools for creating new CWE exercises.

## Files

- **`cwe-exercise-template.ts`** - Template for creating new exercises
- **`generate-exercise.js`** - Script to generate new exercise files
- **`README.md`** - This documentation

## Creating a New Exercise

### Option 1: Using the Generator Script

```bash
cd src/templates
node generate-exercise.js CWE-79 "Cross-Site Scripting"
```

This will:
1. Create a new file in `src/data/exercises/`
2. Pre-fill the template with your CWE ID and name
3. Give you instructions for adding it to the index

### Option 2: Manual Creation

1. **Copy the template:**
   ```bash
   cp src/templates/cwe-exercise-template.ts src/data/exercises/cwe-79-xss.ts
   ```

2. **Replace placeholders:** Edit the new file and replace:
   - `[CWE-XXX]` with actual CWE ID (e.g., `CWE-79`)
   - `[CWE Type] - [Scenario Description]` with descriptive name
   - `[functionName]` with appropriate function name
   - `[VULNERABLE CODE]` with vulnerable code example
   - All option codes and explanations

3. **Add to index:** Edit `src/data/exercises/index.ts`:
   ```typescript
   import { cwe79XSS } from './cwe-79-xss'
   
   export const exercisesList: Exercise[] = [
     cwe89Select,
     cwe89Login,
     cwe79XSS, // Add your new exercise
   ]
   ```

## Template Structure

Each exercise needs:

- **`cweId`** - The CWE identifier (e.g., "CWE-89")
- **`name`** - Descriptive name with scenario
- **`vulnerableFunction`** - Complete function with vulnerability
- **`vulnerableLine`** - The specific line to replace
- **`options`** - Array of 10 options (1 correct, 9 wrong)

**Note**: CWE data (severity, CVEs, attack vectors, mitigation strategies) is automatically fetched from the official MITRE CWE API when exercises load.

## Tips for Good Exercises

### Vulnerable Code
- Use realistic, common vulnerability patterns
- Show clear business logic context
- Make the vulnerability obvious but not trivial

### Wrong Options
- Include common but ineffective "fixes"
- Show subtle variations that still don't work
- Cover different categories of wrong approaches

### Vulnerability Examples
- Focus on realistic, common vulnerability patterns in your code examples
- Show clear business logic context that makes sense to developers
- Use authentic attack scenarios that demonstrate real-world threats

## Directory Structure

```
src/
├── components/
│   └── CWEViewer.vue         # Main interactive component
├── data/
│   └── exercises/
│       ├── index.ts          # Main export file
│       ├── cwe-89-select.ts  # Individual exercises
│       └── cwe-89-login.ts   # More exercises...
├── services/
│   └── cweAPI.ts             # MITRE CWE API integration
└── templates/
    ├── README.md             # This file
    ├── cwe-exercise-template.ts
    └── generate-exercise.js
```

## API-Driven Architecture

The app now uses real-time data from the official MITRE CWE API:
- ✅ **Always current** - CVEs and technical details from official source
- ✅ **No maintenance** - No need to manually update CVE lists
- ✅ **Authoritative** - Direct from MITRE's vulnerability database
- ✅ **Comprehensive** - Includes severity, attack vectors, mitigation strategies

## API Integration

The app automatically fetches comprehensive CWE data including:
- **Related CVEs** - Real vulnerabilities from NIST database
- **Attack vectors** - Common exploitation techniques  
- **Severity ratings** - Risk assessment and likelihood
- **Mitigation strategies** - Proven defense approaches
- **Detection methods** - How to find these vulnerabilities

All data comes directly from MITRE's official CWE API at:
`https://cwe-api.mitre.org/api/v1/cwe/weakness/{id}`