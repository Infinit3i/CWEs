import type { Exercise } from '@/data/exercises'

/**
 * CWE-287 exercise: Cookie-based authentication bypass
 * Based on MITRE demonstrative examples showing client-side authentication weaknesses
 */
export const cwe287CookieAuth: Exercise = {
  cweId: 'CWE-287',
  name: 'Improper Authentication - Cookie-Based Login System',

  vulnerableFunction: `function authenticateUser(username, password) {
  if (username && password) {
    const user = validateCredentials(username, password);
    if (user) {
      document.cookie = "loggedin=true";
      document.cookie = "user=" + username;
      document.cookie = "role=" + user.role;
      return true;
    }
  }
  return false;
}

function checkAdminAccess() {
  const cookies = parseCookies(document.cookie);
  if (cookies.loggedin === "true" && cookies.role === "admin") {
    return true;
  }
  return false;
}`,

  vulnerableLine: `if (cookies.loggedin === "true" && cookies.role === "admin") {`,

  options: [
    {
      code: `function checkAdminAccess() {
  const token = localStorage.getItem('authToken');
  return verifyJWTToken(token) && getTokenRole(token) === 'admin';
}`,
      correct: true,
      explanation: `Validate credentials server-side with expiration`
    },
    // Real MITRE demonstrative examples as wrong answers
    {
      code: `if (cookies.loggedin === "true" && cookies.role === "admin") {
    return true;
}`,
      correct: false,
      explanation: 'Trusting client-side cookies for authentication. Attackers can bypass this by setting Cookie: loggedin=true; role=admin in HTTP requests without valid credentials.'
    },
    {
      code: `const authHeader = getCookie('authenticated');
if (authHeader === 'yes' && getCookie('privilege') === 'admin') {
    return true;
}`,
      correct: false,
      explanation: 'Variation of MITRE cookie vulnerability. Client-controlled authentication state allows trivial bypass by manipulating cookie values.'
    },
    {
      code: `if (sessionStorage.getItem('isLoggedIn') === 'true' &&
    sessionStorage.getItem('userLevel') === 'administrator') {
    return true;
}`,
      correct: false,
      explanation: 'Session storage is client-side and equally manipulable as cookies. Attackers can modify these values through browser developer tools or JavaScript injection.'
    },
    {
      code: `const userCookie = document.cookie.match(/user=([^;]+)/);
if (userCookie && userCookie[1] === 'Administrator') {
    return true;
}`,
      correct: false,
      explanation: 'MITRE-style cookie parsing vulnerability. Simple string matching on client-controlled data provides no real authentication security.'
    },
    {
      code: `if (localStorage.getItem('username') === 'admin' &&
    localStorage.getItem('authenticated') === '1') {
    return true;
}`,
      correct: false,
      explanation: 'Local storage authentication suffers the same client-side trust issues. Values can be modified without server knowledge or validation.'
    },
    {
      code: `const authData = JSON.parse(getCookie('authData'));
if (authData.authenticated && authData.role === 'admin') {
    return true;
}`,
      correct: false,
      explanation: 'JSON-encoded cookies are still client-controlled. Attackers can craft valid JSON with desired authentication values and inject it.'
    },
    {
      code: `if (getCookie('auth_token') && getCookie('is_admin') === 'true') {
    return true;
}`,
      correct: false,
      explanation: 'Presence of a token cookie without server-side verification provides no security. The is_admin flag is client-controllable.'
    },
    {
      code: `const encoded = btoa(getCookie('user_role'));
if (encoded && atob(encoded) === 'admin') {
    return true;
}`,
      correct: false,
      explanation: 'Base64 encoding provides no security - it is encoding, not encryption. Attackers can easily encode their desired role values.'
    },
    {
      code: `if (window.currentUser && window.currentUser.role === 'admin' &&
    window.currentUser.authenticated) {
    return true;
}`,
      correct: false,
      explanation: 'Global JavaScript variables are completely client-controllable through browser console or script injection, providing no authentication security.'
    }
  ]
}