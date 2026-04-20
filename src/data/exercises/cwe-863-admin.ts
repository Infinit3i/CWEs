import type { Exercise } from '@/data/exercises'

/**
 * CWE-863 Incorrect Authorization - Admin Panel Access
 * Based on common authorization bypass patterns
 */
export const cwe863Admin: Exercise = {
  cweId: 'CWE-863',
  name: 'Incorrect Authorization - Admin Dashboard',
  language: 'JavaScript',

  vulnerableFunction: `function accessAdminPanel(username, request) {
  const isAdmin = request.headers['x-admin-user'] === 'true';
  const adminUsers = ['admin', 'superuser', 'root'];

  if (isAdmin || adminUsers.includes(username.toLowerCase())) {
    return {
      success: true,
      data: getSystemConfiguration(),
      adminFeatures: getAllUserData()
    };
  }

  return { error: 'Access denied: Admin privileges required' };
}`,

  vulnerableLine: `const isAdmin = request.headers['x-admin-user'] === 'true';`,

  options: [
    {
      code: `const sessionId = request.cookies.sessionId;
if (!sessionId) return { error: 'Authentication required' };
const session = await validateSession(sessionId);
if (!session.valid || !session.user) return { error: 'Invalid session' };
const userRoles = await getUserRoles(session.user.id);
if (!userRoles.includes('ADMIN')) {
  await logUnauthorizedAccess(session.user.id, 'admin_panel_access');
  return { error: 'Access denied: Admin privileges required' };
}
return { success: true, data: getSystemConfiguration() };`,
      correct: true,
      explanation: `Validate authorization for each resource`
    },
    // Authorization bypass vulnerabilities
    {
      code: `const isAdmin = request.headers['x-admin-user'] === 'true';
if (isAdmin) {
  return { success: true, data: getSystemConfiguration() };
}
return { error: 'Access denied' };`,
      correct: false,
      explanation: 'HTTP headers are client-controlled and can be spoofed. An attacker can add "X-Admin-User: true" to their request headers to gain admin access without proper authentication or authorization.'
    },
    {
      code: `const adminParam = request.query.admin || request.body.admin;
if (adminParam === '1' || adminParam === 'true') {
  return { success: true, data: getSystemConfiguration() };
}
return { error: 'Access denied' };`,
      correct: false,
      explanation: 'URL parameters and POST data are client-controlled. Attackers can simply add ?admin=1 to the URL or include admin=true in POST data to bypass authorization checks.'
    },
    {
      code: `const userAgent = request.headers['user-agent'];
if (userAgent && userAgent.includes('AdminBrowser')) {
  return { success: true, data: getSystemConfiguration() };
}
return { error: 'Access denied' };`,
      correct: false,
      explanation: 'User-Agent headers can be easily spoofed by clients. Attackers can modify their browser\'s User-Agent string to include "AdminBrowser" to gain unauthorized admin access.'
    },
    {
      code: `const referer = request.headers.referer;
if (referer && referer.includes('admin.internal.com')) {
  return { success: true, data: getSystemConfiguration() };
}
return { error: 'Access denied' };`,
      correct: false,
      explanation: 'Referer headers are client-controlled and can be spoofed. Attackers can set a fake referer containing "admin.internal.com" to bypass this authorization check.'
    },
    {
      code: `const clientIp = request.connection.remoteAddress;
const adminIps = ['192.168.1.100', '10.0.0.50'];
if (adminIps.includes(clientIp)) {
  return { success: true, data: getSystemConfiguration() };
}
return { error: 'Access denied' };`,
      correct: false,
      explanation: 'IP-based authorization can be bypassed through proxy servers, VPNs, or IP spoofing. Additionally, X-Forwarded-For headers can be manipulated to make requests appear to come from trusted IPs.'
    },
    {
      code: `const timestamp = parseInt(request.headers['x-timestamp']);
const isRecentRequest = Date.now() - timestamp < 300000; // 5 minutes
if (isRecentRequest) {
  return { success: true, data: getSystemConfiguration() };
}
return { error: 'Access denied' };`,
      correct: false,
      explanation: 'Timestamp-based authorization using client-provided headers is vulnerable. Attackers can set X-Timestamp to the current time to meet the recency requirement without proper authentication.'
    },
    {
      code: `const authCookie = request.cookies.isAuthenticated;
if (authCookie === 'yes' || authCookie === 'true') {
  return { success: true, data: getSystemConfiguration() };
}
return { error: 'Access denied' };`,
      correct: false,
      explanation: 'Cookie-based flags for authentication/authorization are client-controlled. Attackers can set document.cookie="isAuthenticated=true" to bypass the authorization check.'
    },
    {
      code: `const hasAdminFlag = request.body.flags && request.body.flags.includes('ADMIN');
if (hasAdminFlag) {
  return { success: true, data: getSystemConfiguration() };
}
return { error: 'Access denied' };`,
      correct: false,
      explanation: 'Client-provided flags in request bodies can be manipulated. Attackers can include flags:["ADMIN"] in their POST data to gain unauthorized administrative access.'
    },
    {
      code: `const adminToken = request.headers['x-admin-token'];
if (adminToken && adminToken.length > 10) {
  return { success: true, data: getSystemConfiguration() };
}
return { error: 'Access denied' };`,
      correct: false,
      explanation: 'Validating only token length without server-side verification is insufficient. Attackers can provide any string longer than 10 characters in the X-Admin-Token header to bypass authorization.'
    }
  ]
}