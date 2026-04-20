import type { Exercise } from '@/data/exercises'

/**
 * CWE-269: Improper Privilege Management in User Role Assignment
 * Enterprise scenario: Administrative interface with privilege escalation vulnerability
 */
export const cwe269PrivilegeEscalation: Exercise = {
  cweId: 'CWE-269',
  name: 'Privilege Management - User Role Assignment',

  vulnerableFunction: `class UserManagement {
  async assignUserRole(requestingUserId: string, targetUserId: string, newRole: string) {
    const requestingUser = await User.findById(requestingUserId);

    if (!requestingUser) {
      throw new Error('Requesting user not found');
    }

    // Check if requesting user has permission to assign roles
    if (!['admin', 'manager'].includes(requestingUser.role)) {
      throw new Error('Insufficient privileges to assign roles');
    }

    const targetUser = await User.findById(targetUserId);
    if (!targetUser) {
      throw new Error('Target user not found');
    }

    // Update target user's role
    await User.updateOne(
      { _id: targetUserId },
      {
        role: newRole,
        lastModified: new Date(),
        modifiedBy: requestingUserId
      }
    );

    await this.auditLogger.log('ROLE_ASSIGNED', {
      requestingUser: requestingUserId,
      targetUser: targetUserId,
      newRole,
      previousRole: targetUser.role
    });

    return { success: true, targetUserId, newRole };
  }
}`,

  vulnerableLine: `if (!['admin', 'manager'].includes(requestingUser.role)) {`,

  options: [
    {
      code: `if (!this.canAssignRole(requestingUser, targetUser, newRole)) { throw new Error('Insufficient privileges for this role assignment'); }`,
      correct: true,
      explanation: `Correct! Proper privilege validation should check not only if the user can assign roles, but whether they can assign the specific role to the specific target. This prevents managers from creating admin accounts or users from escalating their own privileges.`
    },
    {
      code: `if (!['admin', 'manager'].includes(requestingUser.role)) {`,
      correct: false,
      explanation: 'From MITRE: Incomplete role validation allows managers to assign admin roles, creating privilege escalation. The check does not verify if the requesting user has authority to assign the specific target role.'
    },
    {
      code: `if (requestingUser.role !== 'admin' && newRole === 'admin') { throw new Error('Only admins can create admin users'); } if (!['admin', 'manager'].includes(requestingUser.role)) {`,
      correct: false,
      explanation: 'Partial role validation misses other escalation paths. Managers could still assign higher-privilege roles below admin level, and the check does not prevent self-role modification.'
    },
    {
      code: `if (requestingUserId === targetUserId) { throw new Error('Cannot modify own role'); } if (!['admin', 'manager'].includes(requestingUser.role)) {`,
      correct: false,
      explanation: 'Preventing self-role modification is good but insufficient. Managers can still create new admin accounts or assign admin roles to other users, achieving privilege escalation indirectly.'
    },
    {
      code: `if (requestingUser.role === 'guest') { throw new Error('Guest users cannot assign roles'); } if (!['admin', 'manager'].includes(requestingUser.role)) {`,
      correct: false,
      explanation: 'Excluding specific low-privilege roles does not address the core issue. The validation still allows managers to assign admin roles, creating privilege escalation vulnerabilities.'
    },
    {
      code: `const roleHierarchy = { guest: 1, user: 2, manager: 3, admin: 4 }; if (roleHierarchy[requestingUser.role] <= roleHierarchy[newRole]) { throw new Error('Cannot assign role of equal or higher privilege'); }`,
      correct: false,
      explanation: 'Simple hierarchy comparison prevents direct escalation but misses other privilege management issues. Managers can still assign roles to users who should not have elevated privileges.'
    },
    {
      code: `if (!['admin', 'manager'].includes(requestingUser.role) || (newRole === 'admin' && requestingUser.role !== 'admin')) {`,
      correct: false,
      explanation: 'This is closer but still incomplete. While it prevents managers from creating admin users, it does not validate if the target user should receive the requested role or prevent other forms of privilege escalation.'
    },
    {
      code: `await new Promise(resolve => setTimeout(resolve, 1000)); if (!['admin', 'manager'].includes(requestingUser.role)) {`,
      correct: false,
      explanation: 'Adding delays to privilege checks does not improve security and may worsen it. The fundamental authorization logic remains flawed, allowing inappropriate privilege assignments.'
    }
  ]
}