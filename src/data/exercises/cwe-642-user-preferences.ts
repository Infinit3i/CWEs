import type { Exercise } from '@/data/exercises'

/**
 * CWE-642: External Control of Critical State Data - User Preference Manipulation
 * Security-critical preferences stored in client-controlled data
 */
export const cwe642UserPreferences: Exercise = {
  cweId: 'CWE-642',
  name: 'External Control of Critical State Data - Security Preferences',
  language: 'PHP',

  vulnerableFunction: `function applySecuritySettings(userId, preferences) {
  const userPrefs = preferences || getUserStoredPreferences(userId);

  // Apply security settings from client preferences
  const securitySettings = {
    requireTwoFactor: userPrefs.requireTwoFactor || false,
    sessionTimeout: userPrefs.sessionTimeout || 3600,
    allowedIPs: userPrefs.allowedIPs || [],
    auditLogging: userPrefs.auditLogging !== false,
    passwordComplexity: userPrefs.passwordComplexity || 'medium'
  };

  // Enable enhanced security for admin users
  if (userPrefs.isAdmin) {
    securitySettings.requireTwoFactor = true;
    securitySettings.auditLogging = true;
  }

  updateUserSecurityProfile(userId, securitySettings);
  return securitySettings;
}`,

  vulnerableLine: `if (userPrefs.isAdmin) {`,

  options: [
    {
      code: `if (isAdminUser(userId)) { // Check server authority`,
      correct: true,
      explanation: `Check admin status on server not preferences`
    },
    {
      code: `if (userPrefs.isAdmin) { // Trust client preference`,
      correct: false,
      explanation: 'Critical MITRE trust boundary violation. Users can set isAdmin=true in their preferences to trigger enhanced security settings and potentially bypass normal user restrictions.'
    },
    {
      code: `if (userPrefs.isAdmin && userPrefs.adminVerified) {`,
      correct: false,
      explanation: 'Multiple client-controlled flags still vulnerable. Users can set both isAdmin=true and adminVerified=true in their preferences to gain unauthorized administrative security settings.'
    },
    {
      code: `if (userPrefs.isAdmin === true && typeof userPrefs.isAdmin === 'boolean') {`,
      correct: false,
      explanation: 'Type checking doesn\'t address the trust issue. Users can properly set boolean isAdmin=true in their preferences to trigger administrative security configurations.'
    },
    {
      code: `requireTwoFactor: userPrefs.requireTwoFactor || false,`,
      correct: false,
      explanation: 'Client-controlled security setting allows users to disable two-factor authentication through preference manipulation, weakening account security protection.'
    },
    {
      code: `auditLogging: userPrefs.auditLogging !== false,`,
      correct: false,
      explanation: 'Users can disable audit logging by setting auditLogging=false in preferences, allowing them to avoid security monitoring and compliance tracking.'
    },
    {
      code: `sessionTimeout: userPrefs.sessionTimeout || 3600,`,
      correct: false,
      explanation: 'Client-controlled session timeout allows users to set arbitrary values, potentially maintaining sessions far longer than security policies intend.'
    },
    {
      code: `allowedIPs: userPrefs.allowedIPs || [],`,
      correct: false,
      explanation: 'IP restriction bypass where users can set empty allowedIPs arrays or add unauthorized IP addresses to circumvent network access controls.'
    },
    {
      code: `passwordComplexity: userPrefs.passwordComplexity || 'medium'`,
      correct: false,
      explanation: 'Users can weaken password complexity requirements by setting passwordComplexity to low values, reducing account security below organizational standards.'
    },
    {
      code: `if (userPrefs.isAdmin && userPrefs.adminCode === '12345') {`,
      correct: false,
      explanation: 'Hardcoded admin code in client-controlled preferences is severely vulnerable. Users can examine client code to find the admin code and set both values in their preferences.'
    }
  ]
}