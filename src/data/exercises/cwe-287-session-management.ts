import type { Exercise } from '@/data/exercises'

/**
 * CWE-287 exercise: Session management authentication bypass
 * Based on weak session validation patterns
 */
export const cwe287SessionManagement: Exercise = {
  cweId: 'CWE-287',
  name: 'Improper Authentication - Session Management System',

  vulnerableFunction: `function validateUserSession(req) {
  const sessionId = req.cookies.sessionid;
  const userId = req.cookies.userid;
  const isValid = req.cookies.session_valid;

  if (sessionId && userId && isValid === 'true') {
    return {
      authenticated: true,
      userId: userId,
      sessionId: sessionId
    };
  }

  return { authenticated: false };
}

function hasAdminPrivileges(req) {
  const session = validateUserSession(req);
  return session.authenticated && req.cookies.admin_flag === '1';
}`,

  vulnerableLine: `if (sessionId && userId && isValid === 'true') {`,

  options: [
    {
      code: `function validateUserSession(req) {
  const sessionId = req.cookies.sessionid;
  if (sessionId) {
    const sessionData = getServerSession(sessionId);
    return sessionData && sessionData.valid ?
      { authenticated: true, userId: sessionData.userId, sessionId: sessionId } :
      { authenticated: false };
  }
  return { authenticated: false };
}`,
      correct: true,
      explanation: `Validate credentials server-side with expiration`
    },
    // Session management vulnerabilities
    {
      code: `if (sessionId && userId && isValid === 'true') {
    return { authenticated: true, userId: userId, sessionId: sessionId };
}`,
      correct: false,
      explanation: 'Classic client-side session validation. Attackers can set cookies sessionid=anything; userid=1; session_valid=true to bypass authentication entirely.'
    },
    {
      code: `if (req.headers['session-token'] && req.headers['user-authenticated'] === 'yes') {
    return { authenticated: true, userId: req.headers['user-id'] };
}`,
      correct: false,
      explanation: 'Header-based session management with client-controlled authentication flags. Trivially bypassed by setting appropriate headers in requests.'
    },
    {
      code: `const sessionData = JSON.parse(req.cookies.user_session || '{}');
if (sessionData.valid && sessionData.userId) {
    return { authenticated: true, userId: sessionData.userId };
}`,
      correct: false,
      explanation: 'JSON cookie-based session storage allows complete session forgery. Attackers can craft valid JSON with any desired session properties.'
    },
    {
      code: `if (sessionId.length > 10 && userId && req.cookies.auth_check === 'passed') {
    return { authenticated: true, userId: userId, sessionId: sessionId };
}`,
      correct: false,
      explanation: 'Length-based session validation with client-controlled auth flags. Any string over 10 characters with the right cookies grants access.'
    },
    {
      code: `const sessionKey = req.cookies.session_key;
if (sessionKey && sessionKey.includes('valid') && userId) {
    return { authenticated: true, userId: userId };
}`,
      correct: false,
      explanation: 'String matching in client-controlled session keys. Attackers can set session_key=valid_anything with any user ID to authenticate.'
    },
    {
      code: `if (req.cookies.login_status === 'success' && req.cookies.user_level >= '1') {
    return { authenticated: true, userId: req.cookies.current_user };
}`,
      correct: false,
      explanation: 'Multiple client-controlled cookies determine authentication. All values are manipulable by the client without server verification.'
    },
    {
      code: `const authToken = req.cookies.auth_token;
if (authToken === btoa(userId + ':authenticated')) {
    return { authenticated: true, userId: userId };
}`,
      correct: false,
      explanation: 'Base64 encoding predictable strings provides no cryptographic security. Attackers can easily generate tokens for any user ID.'
    },
    {
      code: `if (sessionId.startsWith('sess_') && req.cookies.verified === '1' && userId) {
    return { authenticated: true, userId: userId, sessionId: sessionId };
}`,
      correct: false,
      explanation: 'Prefix-based session format checking with client-controlled verification flags. Attackers can craft sessions with correct format and set verification cookies.'
    },
    {
      code: `const timestamp = req.cookies.login_time;
if (sessionId && (Date.now() - timestamp) < 3600000 && isValid === 'true') {
    return { authenticated: true, userId: userId };
}`,
      correct: false,
      explanation: 'Client-controlled timestamp validation still relies on client-controlled validity flags. Attackers can set appropriate timestamps along with validity markers.'
    }
  ]
}