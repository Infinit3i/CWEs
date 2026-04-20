export interface CWEExample {
  id: string
  name: string
  description: string
  category: string
  vulnerableCode: {
    language: string
    code: string
    explanation: string
  }
  secureCode: {
    language: string
    code: string
    explanation: string
  }
  keyDifferences: string[]
  remediationSteps: string[]
  severity: 'Low' | 'Medium' | 'High' | 'Critical'
  owasp: string[]
}