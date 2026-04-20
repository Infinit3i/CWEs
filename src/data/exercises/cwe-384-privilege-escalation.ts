import type { Exercise } from '@/data/exercises'

/**
 * CWE-384 Exercise 2: Session Fixation in Privilege Escalation
 * Based on maintaining session during role elevation
 */
export const cwe384PrivilegeEscalation: Exercise = {
  cweId: 'CWE-384',
  name: 'Session Fixation - Admin Privilege Escalation',

  vulnerableFunction: `function elevateToAdmin(sessionId, adminPassword) {
  const session = sessions[sessionId];

  if (!session || !session.authenticated) {
    return { success: false, error: 'Not authenticated' };
  }

  // Verify admin password
  if (validateAdminPassword(adminPassword)) {
    // Elevate user privileges in existing session
    session.role = 'admin';
    session.adminAccess = true;
    session.elevatedAt = Date.now();
    session.permissions = ['read', 'write', 'delete', 'admin'];

    return {
      success: true,
      sessionId: sessionId,
      role: 'admin'
    };
  }

  return { success: false, error: 'Invalid admin password' };
}`,

  vulnerableLine: `session.role = 'admin';`,

  options: [
    {
      code: `// Generate new session for elevated privileges
const newAdminSessionId = generateSecureSessionId();
const newSession = {
  userId: session.userId,
  username: session.username,
  role: 'admin',
  adminAccess: true,
  elevatedAt: Date.now(),
  permissions: ['read', 'write', 'delete', 'admin'],
  authenticated: true
};

sessions[newAdminSessionId] = newSession;
delete sessions[sessionId]; // Invalidate old session

return {
  success: true,
  sessionId: newAdminSessionId,
  role: 'admin'
};`,
      correct: true,
      explanation: `Correct! Creating a new session ID for elevated privileges prevents session fixation during privilege escalation. This ensures attackers cannot use a pre-existing session to gain admin access.`
    },
    {
      code: `session.role = 'admin';
session.adminAccess = true;`,
      correct: false,
      explanation: 'Direct from MITRE: Elevating privileges in existing session enables session fixation. Attackers with the original session ID automatically gain admin access without re-authentication.'
    },
    {
      code: `Object.assign(session, {
  role: 'admin',
  adminAccess: true,
  permissions: ['read', 'write', 'delete', 'admin']
});`,
      correct: false,
      explanation: 'Using Object.assign to update session with admin privileges still maintains the same session ID, allowing session fixation attacks.'
    },
    {
      code: `const adminSession = { ...session, role: 'admin', adminAccess: true };
sessions[sessionId] = adminSession;`,
      correct: false,
      explanation: 'Spreading existing session data while adding admin privileges does not change the session ID, keeping the session fixation vulnerability.'
    },
    {
      code: `session.previousRole = session.role;
session.role = 'admin';
session.adminAccess = true;`,
      correct: false,
      explanation: 'Tracking previous roles does not prevent session fixation. The session ID remains the same and can be hijacked.'
    },
    {
      code: `if (session.role !== 'admin') {
  session.role = 'admin';
  session.adminAccess = true;
  session.elevationCount = (session.elevationCount || 0) + 1;
}`,
      correct: false,
      explanation: 'Conditional elevation and tracking attempts do not prevent session fixation. The fundamental issue is reusing the same session ID.'
    },
    {
      code: `const elevatedSession = JSON.parse(JSON.stringify(session));
elevatedSession.role = 'admin';
elevatedSession.adminAccess = true;
sessions[sessionId] = elevatedSession;`,
      correct: false,
      explanation: 'Deep cloning session data while maintaining the same session ID does not prevent session fixation attacks.'
    },
    {
      code: `try {
  session.role = 'admin';
  session.adminAccess = true;
  session.secureElevation = true;
} catch (e) {
  return { success: false, error: 'Elevation failed' };
}`,
      correct: false,
      explanation: 'Error handling and security flags do not prevent session fixation. The session ID is still reused for elevated privileges.'
    },
    {
      code: `session.roles = session.roles || [];
if (!session.roles.includes('admin')) {
  session.roles.push('admin');
  session.adminAccess = true;
}`,
      correct: false,
      explanation: 'Using role arrays instead of a single role property does not prevent session fixation. The session ID remains unchanged.'
    },
    {
      code: `sessions[sessionId + '_admin'] = {
  ...session,
  role: 'admin',
  adminAccess: true
};`,
      correct: false,
      explanation: 'Creating a derived session ID by appending to the original ID is predictable and does not prevent session fixation attacks.'
    }
  ]
}