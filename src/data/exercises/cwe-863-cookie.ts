import type { Exercise } from '@/data/exercises'

/**
 * CWE-863 Incorrect Authorization - Cookie-Based Access Control
 * Based on MITRE demonstrative example for medical records access
 */
export const cwe863Cookie: Exercise = {
  cweId: 'CWE-863',
  name: 'Incorrect Authorization - Medical Records Access',

  vulnerableFunction: `function viewMedicalRecord(patientId, request) {
  const role = request.cookies.role;
  if (!role) {
    const userRole = getRole('user');
    if (userRole) {
      response.setHeader('Set-Cookie', \`role=\${userRole}; Max-Age=7200\`);
      role = userRole;
    } else {
      return { error: 'Please login' };
    }
  }

  if (role === 'Reader') {
    return getMedicalHistory(patientId);
  } else {
    return { error: 'You are not authorized to view this record' };
  }
}`,

  vulnerableLine: `const role = request.cookies.role;`,

  options: [
    {
      code: `const sessionId = request.cookies.sessionId;
if (!sessionId) return { error: 'Please login' };
const session = await getServerSession(sessionId);
if (!session || !session.user) return { error: 'Invalid session' };
const permissions = await getUserPermissions(session.user.id);
if (!permissions.includes('medical:read')) {
  return { error: 'You are not authorized to view this record' };
}
return getMedicalHistory(patientId);`,
      correct: true,
      explanation: `Validate authorization for each resource`
    },
    // MITRE demonstrative example as wrong answer
    {
      code: `const role = request.cookies.role;
if (role === 'Reader') {
  return getMedicalHistory(patientId);
} else {
  return { error: 'You are not authorized to view this record' };
}`,
      correct: false,
      explanation: 'Trusting client-side cookies for authorization is vulnerable. An attacker can simply set document.cookie="role=Reader" to bypass authorization and access medical records without proper authentication.'
    },
    {
      code: `const role = request.headers['x-user-role'];
if (role === 'Reader' || role === 'Admin') {
  return getMedicalHistory(patientId);
}
return { error: 'Access denied' };`,
      correct: false,
      explanation: 'HTTP headers are client-controlled and can be easily spoofed. An attacker can add "X-User-Role: Reader" to their request headers to gain unauthorized access to medical records.'
    },
    {
      code: `const userToken = request.cookies.token;
const decodedRole = Buffer.from(userToken || '', 'base64').toString();
if (decodedRole === 'Reader') {
  return getMedicalHistory(patientId);
}
return { error: 'Access denied' };`,
      correct: false,
      explanation: 'Base64 encoding is not encryption or authentication. Attackers can easily encode "Reader" as Base64 and set the token cookie to gain unauthorized access.'
    },
    {
      code: `const role = request.body.userRole || request.cookies.role;
if (role && ['Reader', 'Admin'].includes(role)) {
  return getMedicalHistory(patientId);
}
return { error: 'Access denied' };`,
      correct: false,
      explanation: 'Both request body and cookie data are client-controlled. Attackers can manipulate either POST data or cookies to set their role and bypass authorization checks.'
    },
    {
      code: `const authHeader = request.headers.authorization;
if (authHeader && authHeader.includes('Bearer Reader')) {
  return getMedicalHistory(patientId);
}
return { error: 'Access denied' };`,
      correct: false,
      explanation: 'String matching in authorization headers is not secure authentication. Attackers can craft headers like "Authorization: Bearer Reader" without valid tokens to access protected resources.'
    },
    {
      code: `const role = localStorage.getItem('userRole');
if (role === 'Reader') {
  return getMedicalHistory(patientId);
}
return { error: 'Access denied' };`,
      correct: false,
      explanation: 'localStorage is client-side storage that can be manipulated by users. Attackers can use browser developer tools to set localStorage.userRole = "Reader" and bypass authorization.'
    },
    {
      code: `const userPermissions = request.cookies.permissions?.split(',');
if (userPermissions?.includes('medical:read')) {
  return getMedicalHistory(patientId);
}
return { error: 'Access denied' };`,
      correct: false,
      explanation: 'Storing permissions in cookies allows client-side manipulation. Attackers can modify their cookies to include "medical:read" permission without server-side validation.'
    },
    {
      code: `const userId = request.cookies.userId;
const role = await getUserRole(userId);
if (role === 'Reader') {
  return getMedicalHistory(patientId);
}
return { error: 'Access denied' };`,
      correct: false,
      explanation: 'While this performs server-side role lookup, trusting the userId from cookies is dangerous. Attackers can change their userId cookie to impersonate other users, including those with Reader privileges.'
    },
    {
      code: `const sessionData = JSON.parse(request.cookies.session || '{}');
if (sessionData.role === 'Reader' && sessionData.authenticated) {
  return getMedicalHistory(patientId);
}
return { error: 'Access denied' };`,
      correct: false,
      explanation: 'JSON session data in cookies can be manipulated by clients. Attackers can set their session cookie to {"role":"Reader","authenticated":true} to bypass authentication and authorization checks.'
    }
  ]
}