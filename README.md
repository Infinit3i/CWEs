# CWE Learning Platform

An interactive Vue TypeScript application for learning Common Weakness Enumerations (CWEs) - security vulnerabilities in code.

## Features

- **Interactive Learning**: Compare vulnerable vs secure code side-by-side
- **Clear Explanations**: Understanding what makes code vulnerable and how to fix it
- **Key Differences Highlighting**: Spot the exact changes needed for security
- **Remediation Steps**: Step-by-step guide to fix vulnerabilities
- **Severity Ratings**: Understand the impact of different vulnerabilities
- **OWASP Mapping**: See how CWEs relate to OWASP Top 10

## Current Exercises

### CWE-89: SQL Injection
1. **User Data Query** - Basic SELECT statement vulnerability
2. **Login Authentication** - Authentication bypass scenario  
3. **User Profile Update** - Multiple UPDATE statements (multi-line vulnerability)
4. **Data Deletion** - DELETE statement with multiple parameters
5. **Order Creation** - Multiple INSERT statements (multi-line vulnerability)
6. **Product Search** - Complex search with LIKE, filtering, and ORDER BY

Navigate between exercises using the Previous/Next buttons in the app.

## Getting Started

1. **Install Dependencies**
   ```bash
   npm install
   ```

2. **Start Development Server**
   ```bash
   npm run dev
   ```

3. **Open in Browser**
   Navigate to http://localhost:5173/

## Adding New Exercises

The app now uses a modular structure with templates for easy expansion:

### Quick Start
```bash
cd src/templates
node generate-exercise.js CWE-79 "Cross-Site Scripting"
```

### Manual Process
1. **Copy Template**: Use `src/templates/cwe-exercise-template.ts`
2. **Fill in Details**: Replace all `[PLACEHOLDER]` values
3. **Add to Index**: Import in `src/data/exercises/index.ts`

**Note**: CWE data (CVEs, severity, mitigation) is automatically fetched from the MITRE API.

### Exercise Structure
```typescript
{
  cweId: 'CWE-XXX',
  name: 'Vulnerability Type - Scenario', 
  vulnerableFunction: `function example() { /* vulnerable code */ }`,
  vulnerableLine: `const vulnerable = "line to replace";`,
  options: [ /* 10 options: 1 correct, 9 wrong */ ]
  // CWE data automatically fetched from MITRE API
}
```

## Suggested CWEs to Add Next

- **CWE-79**: Cross-Site Scripting (XSS)
- **CWE-22**: Path Traversal
- **CWE-78**: OS Command Injection
- **CWE-502**: Deserialization of Untrusted Data
- **CWE-862**: Missing Authorization
- **CWE-798**: Hard-coded Credentials
- **CWE-400**: Uncontrolled Resource Consumption
- **CWE-611**: XML External Entity (XXE) Injection

## Architecture

```
src/
├── components/
│   └── CWEViewer.vue           # Main interactive component
├── data/
│   ├── exercises.ts            # TypeScript interfaces & main export
│   └── exercises/
│       ├── index.ts            # Exercise registry
│       ├── cwe-89-select.ts    # Individual exercise files
│       └── cwe-89-login.ts     # More exercises...
├── services/
│   └── cweAPI.ts               # MITRE CWE API integration
├── templates/
│   ├── README.md               # Template documentation
│   ├── cwe-exercise-template.ts # Exercise template
│   └── generate-exercise.js    # Generator script
├── App.vue                     # Root component
├── main.ts                     # Application entry point
└── style.css                   # Global styles
```

### API-Driven Architecture
- **Real-time data** from official MITRE CWE API
- **Always current** CVEs and technical details  
- **No maintenance** of static CVE lists
- **Comprehensive** severity, attack vectors, mitigation strategies

## Building for Production

```bash
npm run build
```

## Technology Stack

- **Vue 3** - Reactive UI framework
- **TypeScript** - Type safety
- **Vite** - Fast development and building
- **CSS3** - Modern styling with gradients and animations

## Learning Approach

1. **See the Problem**: Study the vulnerable code example
2. **Understand the Fix**: Examine the secure version
3. **Identify Patterns**: Learn what specific changes make code secure
4. **Practice Recognition**: Apply knowledge to spot similar issues in real code

This platform helps security professionals, developers, and students understand common vulnerabilities through hands-on code examples.