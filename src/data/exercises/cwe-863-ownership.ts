import type { Exercise } from '@/data/exercises'

/**
 * CWE-863 Incorrect Authorization - Resource Ownership Validation
 * Based on common ownership bypass vulnerabilities
 */
export const cwe863Ownership: Exercise = {
  cweId: 'CWE-863',
  name: 'Incorrect Authorization - File Ownership Validation',
  language: 'JavaScript',

  vulnerableFunction: `function deleteUserFile(fileId, request) {
  const claimedUserId = request.headers['x-user-id'];
  const file = getFileMetadata(fileId);

  if (!file) {
    return { error: 'File not found' };
  }

  // Check if user owns the file or is admin
  const isAdmin = request.query.admin === 'true';
  const isOwner = file.ownerId === claimedUserId;

  if (isOwner || isAdmin) {
    deleteFile(fileId);
    return {
      success: true,
      message: \`File \${fileId} deleted successfully\`,
      deletedBy: claimedUserId
    };
  }

  return { error: 'You can only delete your own files' };
}`,

  vulnerableLine: `const claimedUserId = request.headers['x-user-id'];`,

  options: [
    {
      code: `const authToken = request.headers.authorization?.split(' ')[1];
if (!authToken) return { error: 'Authentication required' };
const tokenPayload = await verifyJwtToken(authToken);
if (!tokenPayload.valid) return { error: 'Invalid token' };
const file = getFileMetadata(fileId);
if (!file) return { error: 'File not found' };
const isOwner = file.ownerId === tokenPayload.userId;
const isAdmin = tokenPayload.roles?.includes('ADMIN');
if (!isOwner && !isAdmin) {
  await logUnauthorizedAccess(tokenPayload.userId, 'file_delete', fileId);
  return { error: 'You can only delete your own files' };
}
deleteFile(fileId);
return { success: true, message: \`File \${fileId} deleted\` };`,
      correct: true,
      explanation: `Validate authorization for each resource`
    },
    // Authorization bypass vulnerabilities
    {
      code: `const claimedUserId = request.headers['x-user-id'];
const file = getFileMetadata(fileId);
if (file.ownerId === claimedUserId) {
  deleteFile(fileId);
  return { success: true, message: 'File deleted' };
}
return { error: 'Access denied' };`,
      correct: false,
      explanation: 'User ID headers are client-controlled and can be spoofed. An attacker can set the X-User-ID header to match any file\'s owner ID to delete files belonging to other users.'
    },
    {
      code: `const isOwner = request.body.isFileOwner === true;
if (isOwner) {
  deleteFile(fileId);
  return { success: true, message: 'File deleted' };
}
return { error: 'Access denied' };`,
      correct: false,
      explanation: 'POST data is client-controlled. Attackers can include isFileOwner: true in their request body to bypass ownership checks and delete any file.'
    },
    {
      code: `const userSession = request.cookies.userId;
const file = getFileMetadata(fileId);
if (file.ownerId === userSession) {
  deleteFile(fileId);
  return { success: true, message: 'File deleted' };
}
return { error: 'Access denied' };`,
      correct: false,
      explanation: 'User ID cookies can be manipulated by clients. Attackers can change their userId cookie to match any file owner and delete files they don\'t own.'
    },
    {
      code: `const ownershipToken = request.headers['x-ownership-proof'];
if (ownershipToken === 'VALID_OWNER') {
  deleteFile(fileId);
  return { success: true, message: 'File deleted' };
}
return { error: 'Access denied' };`,
      correct: false,
      explanation: 'Static ownership tokens in headers are client-controlled. Attackers can set X-Ownership-Proof to "VALID_OWNER" to bypass ownership validation without proper authentication.'
    },
    {
      code: `const requestingUser = request.query.userId;
const fileOwner = getFileOwner(fileId);
if (requestingUser === fileOwner) {
  deleteFile(fileId);
  return { success: true, message: 'File deleted' };
}
return { error: 'Access denied' };`,
      correct: false,
      explanation: 'URL parameters are client-controlled. Attackers can append ?userId=<target_owner> to their request to claim ownership of any file and delete it.'
    },
    {
      code: `const authLevel = parseInt(request.headers['x-auth-level']);
if (authLevel >= 5) {
  deleteFile(fileId);
  return { success: true, message: 'File deleted' };
}
return { error: 'Access denied' };`,
      correct: false,
      explanation: 'Authentication level headers are client-controlled. Attackers can set X-Auth-Level to any value >= 5 to gain sufficient privileges to delete any file.'
    },
    {
      code: `const userCredentials = JSON.parse(request.body.credentials || '{}');
if (userCredentials.verified === true) {
  deleteFile(fileId);
  return { success: true, message: 'File deleted' };
}
return { error: 'Access denied' };`,
      correct: false,
      explanation: 'Credentials in POST bodies are client-controlled. Attackers can include credentials: {verified: true} in their request to bypass authentication and delete any file.'
    },
    {
      code: `const signature = request.headers['x-request-signature'];
if (signature && signature.length > 20) {
  deleteFile(fileId);
  return { success: true, message: 'File deleted' };
}
return { error: 'Access denied' };`,
      correct: false,
      explanation: 'Request signatures without proper cryptographic verification are meaningless. Attackers can provide any string longer than 20 characters in the X-Request-Signature header to bypass authorization.'
    },
    {
      code: `const filePermissions = request.cookies.permissions?.split(',');
if (filePermissions?.includes('delete')) {
  deleteFile(fileId);
  return { success: true, message: 'File deleted' };
}
return { error: 'Access denied' };`,
      correct: false,
      explanation: 'Permission cookies are client-controlled. Attackers can set document.cookie="permissions=delete,read,write" to grant themselves all file permissions including deletion rights.'
    }
  ]
}