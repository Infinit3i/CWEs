# CWE Learning Platform

Interactive learning platform for Common Weakness Enumerations (CWEs) - the most dangerous software security vulnerabilities.

## What is this?

A hands-on educational tool where you drag and drop secure code fixes onto vulnerable functions. Learn to identify and fix real security vulnerabilities through interactive exercises based on authentic examples from MITRE's official CWE database.

## How it works

1. **See vulnerable code** - Real-world security flaws in context
2. **Drag the fix** - Choose the correct secure replacement from multiple options  
3. **Learn why** - Get detailed explanations of what makes code secure vs vulnerable
4. **Explore real attacks** - See actual CVEs and attack vectors from MITRE

## Current Coverage

**SQL Injection (CWE-89)**: 6 exercises covering authentication, data queries, updates, and complex searches

**Cross-Site Scripting (CWE-79)**: User input handling and output encoding

**More coming**: Working toward complete coverage of OWASP Top 25 vulnerabilities

## Features

✅ **Random exercises** - No linear progression, reinforces learning through repetition  
✅ **Real MITRE data** - Official CVEs, severity ratings, and attack patterns  
✅ **Authentic examples** - Vulnerable code patterns from actual security incidents  
✅ **Technical depth** - Learn *why* fixes work at a technical level

## Quick Start

```bash
npm install
npm run dev
# Open http://localhost:5173
```

Deploy to GitHub Pages: Push to main branch with Actions enabled.

---

*Built for security professionals, developers, and students learning application security.*