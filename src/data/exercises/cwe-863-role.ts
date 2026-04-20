import type { Exercise } from '@/data/exercises'

/**
 * CWE-863 Incorrect Authorization - Role-Based Access Control
 * Based on common RBAC implementation vulnerabilities
 */
export const cwe863Role: Exercise = {
  cweId: 'CWE-863',
  name: 'Incorrect Authorization - Document Access Control',
  language: 'JavaScript',

  vulnerableFunction: `function accessDocument(documentId, request) {
  const userRoles = request.query.roles?.split(',') || [];
  const documentLevel = getDocumentSecurityLevel(documentId);

  const roleHierarchy = {
    'guest': 1,
    'user': 2,
    'manager': 3,
    'admin': 4
  };

  const maxUserLevel = Math.max(...userRoles.map(role => roleHierarchy[role] || 0));

  if (maxUserLevel >= documentLevel) {
    return {
      success: true,
      document: getDocumentContent(documentId),
      accessLevel: maxUserLevel
    };
  }

  return { error: 'Insufficient privileges to access this document' };
}`,

  vulnerableLine: `const userRoles = request.query.roles?.split(',') || [];`,

  options: [
    {
      code: `const authToken = request.headers.authorization?.replace('Bearer ', '');
if (!authToken) return { error: 'Authentication required' };
const payload = await verifyJwtToken(authToken);
if (!payload.valid) return { error: 'Invalid authentication token' };
const userRoles = await getUserRoles(payload.userId);
const hasAccess = await checkDocumentAccess(documentId, userRoles);
if (!hasAccess) {
  await auditLog(payload.userId, 'DENIED', 'document_access', documentId);
  return { error: 'Insufficient privileges to access this document' };
}
return { success: true, document: getDocumentContent(documentId) };`,
      correct: true,
      explanation: `Validate authorization for each resource`
    },
    // Authorization bypass vulnerabilities
    {
      code: `const userRoles = request.query.roles?.split(',') || [];
const documentLevel = getDocumentSecurityLevel(documentId);
const hasManagerRole = userRoles.includes('manager');
if (hasManagerRole && documentLevel <= 3) {
  return { success: true, document: getDocumentContent(documentId) };
}
return { error: 'Access denied' };`,
      correct: false,
      explanation: 'URL query parameters are client-controlled. An attacker can append ?roles=manager to any request to gain manager-level access to documents without proper authentication or authorization.'
    },
    {
      code: `const roleHeader = request.headers['x-user-roles'];
const userRoles = roleHeader ? JSON.parse(roleHeader) : [];
if (userRoles.includes('admin')) {
  return { success: true, document: getDocumentContent(documentId) };
}
return { error: 'Access denied' };`,
      correct: false,
      explanation: 'HTTP headers are client-controlled and can be spoofed. Attackers can set X-User-Roles to ["admin"] to gain administrative access to any document without proper authorization.'
    },
    {
      code: `const sessionData = request.body.session || {};
const userLevel = sessionData.accessLevel || 0;
const documentLevel = getDocumentSecurityLevel(documentId);
if (userLevel >= documentLevel) {
  return { success: true, document: getDocumentContent(documentId) };
}
return { error: 'Access denied' };`,
      correct: false,
      explanation: 'Session data in POST bodies is client-controlled. Attackers can include session: {accessLevel: 999} in their request body to bypass all document security levels.'
    },
    {
      code: `const userClaims = request.cookies.claims ? JSON.parse(request.cookies.claims) : {};
if (userClaims.roles && userClaims.roles.includes('admin')) {
  return { success: true, document: getDocumentContent(documentId) };
}
return { error: 'Access denied' };`,
      correct: false,
      explanation: 'Cookie-based claims are client-controlled. Attackers can set document.cookie="claims={\\"roles\\":[\\"admin\\"]}" to grant themselves admin privileges without proper authentication.'
    },
    {
      code: `const authLevel = parseInt(request.headers['authorization-level']) || 0;
const documentLevel = getDocumentSecurityLevel(documentId);
if (authLevel >= documentLevel) {
  return { success: true, document: getDocumentContent(documentId) };
}
return { error: 'Access denied' };`,
      correct: false,
      explanation: 'Authorization-level headers are client-controlled. Attackers can set "Authorization-Level: 999" to claim maximum privileges and access any document regardless of its security level.'
    },
    {
      code: `const isPrivileged = request.query.privileged === 'true';
if (isPrivileged) {
  return { success: true, document: getDocumentContent(documentId) };
}
return { error: 'Access denied' };`,
      correct: false,
      explanation: 'URL parameters are completely client-controlled. Adding ?privileged=true to any request would grant access to documents without any authentication or authorization validation.'
    },
    {
      code: `const userToken = request.headers['x-access-token'];
const decodedRoles = userToken ? Buffer.from(userToken, 'base64').toString().split(',') : [];
if (decodedRoles.includes('manager')) {
  return { success: true, document: getDocumentContent(documentId) };
}
return { error: 'Access denied' };`,
      correct: false,
      explanation: 'Base64 encoding is not encryption or authentication. Attackers can encode "manager" as Base64 and set the X-Access-Token header to gain manager privileges without proper verification.'
    },
    {
      code: `const permissions = request.body.permissions || [];
const hasDocumentAccess = permissions.some(p => p.resource === 'document' && p.action === 'read');
if (hasDocumentAccess) {
  return { success: true, document: getDocumentContent(documentId) };
}
return { error: 'Access denied' };`,
      correct: false,
      explanation: 'Permissions in request bodies are client-controlled. Attackers can include permissions: [{resource: "document", action: "read"}] in POST data to grant themselves document access.'
    },
    {
      code: `const referrer = request.headers.referer;
if (referrer && referrer.includes('admin-dashboard')) {
  return { success: true, document: getDocumentContent(documentId) };
}
return { error: 'Access denied' };`,
      correct: false,
      explanation: 'Referer headers can be easily spoofed by clients. Attackers can set a fake referer containing "admin-dashboard" to make their request appear to come from an administrative interface.'
    }
  ]
}