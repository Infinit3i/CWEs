import type { Exercise } from '@/data/exercises'

/**
 * CWE-863 Incorrect Authorization - API Access Control
 * Based on common API authorization bypass patterns
 */
export const cwe863Api: Exercise = {
  cweId: 'CWE-863',
  name: 'Incorrect Authorization - API Endpoint Protection',

  vulnerableFunction: `function deleteUserAccount(userId, request) {
  const requestingUserId = request.headers['user-id'];
  const apiKey = request.headers['x-api-key'];

  // Allow deletion if requesting user matches or has valid API key
  if (requestingUserId === userId || apiKey === 'DELETE_API_KEY_2024') {
    return {
      success: true,
      message: \`Account \${userId} has been deleted\`,
      deletedUser: removeUser(userId)
    };
  }

  return { error: 'Unauthorized: Cannot delete this account' };
}`,

  vulnerableLine: `const requestingUserId = request.headers['user-id'];`,

  options: [
    {
      code: `const authToken = request.headers.authorization?.split(' ')[1];
if (!authToken) return { error: 'Authentication required' };
const tokenData = await verifyJwtToken(authToken);
if (!tokenData.valid) return { error: 'Invalid token' };
const canDelete = tokenData.userId === userId || tokenData.roles.includes('ADMIN');
if (!canDelete) {
  await logUnauthorizedAttempt(tokenData.userId, 'delete_user', userId);
  return { error: 'Unauthorized: Cannot delete this account' };
}
return { success: true, message: \`Account \${userId} deleted\` };`,
      correct: true,
      explanation: `Validate authorization for each resource`
    },
    // Authorization bypass vulnerabilities
    {
      code: `const requestingUserId = request.headers['user-id'];
if (requestingUserId === userId) {
  return { success: true, message: \`Account \${userId} deleted\` };
}
return { error: 'Unauthorized' };`,
      correct: false,
      explanation: 'User-ID headers are client-controlled and can be spoofed. An attacker can set the "User-ID" header to match any target userId to delete arbitrary accounts without proper authentication.'
    },
    {
      code: `const isOwner = request.body.isAccountOwner === true;
if (isOwner) {
  return { success: true, message: \`Account \${userId} deleted\` };
}
return { error: 'Unauthorized' };`,
      correct: false,
      explanation: 'POST data is client-controlled. Attackers can include isAccountOwner: true in their request body to bypass authorization and delete any user account.'
    },
    {
      code: `const authLevel = parseInt(request.headers['x-auth-level']);
if (authLevel >= 5) {
  return { success: true, message: \`Account \${userId} deleted\` };
}
return { error: 'Unauthorized' };`,
      correct: false,
      explanation: 'Custom authentication level headers are client-controlled. Attackers can set "X-Auth-Level: 10" or any value >= 5 to gain unauthorized access to the delete function.'
    },
    {
      code: `const sessionId = request.cookies.session;
const userRole = getUserRoleFromSession(sessionId);
if (userRole === 'admin') {
  return { success: true, message: \`Account \${userId} deleted\` };
}
return { error: 'Unauthorized' };`,
      correct: false,
      explanation: 'If session cookies can be manipulated or if getUserRoleFromSession() trusts client data, this is vulnerable. Additionally, there\'s no validation that the session is valid or belongs to the requesting user.'
    },
    {
      code: `const clientCert = request.headers['x-client-certificate'];
if (clientCert && clientCert.includes('CN=admin')) {
  return { success: true, message: \`Account \${userId} deleted\` };
}
return { error: 'Unauthorized' };`,
      correct: false,
      explanation: 'Client certificate headers are client-controlled and can be spoofed. Attackers can set a fake certificate header containing "CN=admin" to bypass authorization checks.'
    },
    {
      code: `const requestOrigin = request.headers.origin;
if (requestOrigin === 'https://admin.company.com') {
  return { success: true, message: \`Account \${userId} deleted\` };
}
return { error: 'Unauthorized' };`,
      correct: false,
      explanation: 'Origin headers can be spoofed by clients. Attackers can set the Origin header to "https://admin.company.com" to make their request appear to come from a trusted admin interface.'
    },
    {
      code: `const userAgent = request.headers['user-agent'];
if (userAgent && userAgent.includes('AdminTool/1.0')) {
  return { success: true, message: \`Account \${userId} deleted\` };
}
return { error: 'Unauthorized' };`,
      correct: false,
      explanation: 'User-Agent strings are easily modified by clients. Attackers can change their User-Agent to include "AdminTool/1.0" to bypass this authorization check.'
    },
    {
      code: `const permissions = JSON.parse(request.headers['x-permissions'] || '[]');
if (permissions.includes('user:delete')) {
  return { success: true, message: \`Account \${userId} deleted\` };
}
return { error: 'Unauthorized' };`,
      correct: false,
      explanation: 'Permissions sent in headers are client-controlled. Attackers can set X-Permissions to ["user:delete"] to grant themselves the necessary permission to delete accounts.'
    },
    {
      code: `const ipAddress = request.connection.remoteAddress;
const trustedIps = await getTrustedIPs();
if (trustedIps.includes(ipAddress)) {
  return { success: true, message: \`Account \${userId} deleted\` };
}
return { error: 'Unauthorized' };`,
      correct: false,
      explanation: 'IP-based authorization can be bypassed through proxies, VPNs, or by manipulating X-Forwarded-For headers. IP addresses alone are not sufficient for authorization of sensitive operations like account deletion.'
    }
  ]
}