import type { Exercise } from '@/data/exercises'

/**
 * CWE-269: Improper Privilege Management in Password Reset Function
 * Enterprise scenario: Administrative password reset without proper authorization
 */
export const cwe269PasswordReset: Exercise = {
  cweId: 'CWE-269',
  name: 'Privilege Management - Password Reset Function',

  vulnerableFunction: `class AdminController {
  async resetUserPassword(requestingUserId: string, targetUserId: string, newPassword: string) {
    const requestingUser = await User.findById(requestingUserId);

    if (!requestingUser) {
      throw new Error('Requesting user not found');
    }

    // Check if requesting user has administrative privileges
    if (requestingUser.role === 'guest' || requestingUser.role === 'user') {
      throw new Error('Insufficient privileges');
    }

    const targetUser = await User.findById(targetUserId);
    if (!targetUser) {
      throw new Error('Target user not found');
    }

    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update user password
    await User.updateOne(
      { _id: targetUserId },
      {
        password: hashedPassword,
        passwordResetAt: new Date(),
        passwordResetBy: requestingUserId,
        mustChangePassword: true
      }
    );

    await this.auditLogger.log('PASSWORD_RESET', {
      requestingUser: requestingUserId,
      targetUser: targetUserId,
      timestamp: new Date()
    });

    return { success: true, message: 'Password reset successfully' };
  }
}`,

  vulnerableLine: `if (requestingUser.role === 'guest' || requestingUser.role === 'user') {`,

  options: [
    {
      code: `if (!this.canResetPassword(requestingUser, targetUser)) { throw new Error('Insufficient privileges to reset this user\'s password'); }`,
      correct: true,
      explanation: `Correct! Password reset authorization should validate both the requesting user's privileges and whether they have authority over the target user. This prevents operators from resetting admin passwords and ensures proper hierarchical control.`
    },
    {
      code: `if (requestingUser.role === 'guest' || requestingUser.role === 'user') {`,
      correct: false,
      explanation: 'From MITRE: "Code doesn\'t verify the target user\'s role; OPERATOR can reset ADMIN passwords." Incomplete privilege checking allows lower-privilege users to reset higher-privilege accounts.'
    },
    {
      code: `if (requestingUser.role !== 'admin' && targetUser.role === 'admin') { throw new Error('Cannot reset admin passwords'); } if (requestingUser.role === 'guest' || requestingUser.role === 'user') {`,
      correct: false,
      explanation: 'Partial protection for admin accounts is insufficient. Operators can still reset other privileged accounts like managers, and the hierarchy validation is incomplete.'
    },
    {
      code: `if (requestingUserId === targetUserId) { throw new Error('Cannot reset own password through admin function'); } if (requestingUser.role === 'guest' || requestingUser.role === 'user') {`,
      correct: false,
      explanation: 'Preventing self-password reset does not address the core privilege issue. Lower-privilege users can still reset passwords of higher-privilege accounts they should not control.'
    },
    {
      code: `const allowedRoles = ['admin', 'manager', 'operator']; if (!allowedRoles.includes(requestingUser.role)) {`,
      correct: false,
      explanation: 'Expanding allowed roles without hierarchy validation worsens the problem. Now more users can reset passwords inappropriately, including resetting accounts with higher privileges.'
    },
    {
      code: `if (requestingUser.department !== targetUser.department) { throw new Error('Can only reset passwords within same department'); } if (requestingUser.role === 'guest' || requestingUser.role === 'user') {`,
      correct: false,
      explanation: 'Department-based restrictions do not address privilege hierarchy issues. Users can still reset passwords of higher-privilege accounts within their department.'
    },
    {
      code: `const currentTime = new Date(); if (targetUser.lastLogin && (currentTime.getTime() - targetUser.lastLogin.getTime()) < 86400000) { throw new Error('Cannot reset recently active user password'); }`,
      correct: false,
      explanation: 'Activity-based restrictions do not validate privilege hierarchy. The fundamental authorization flaw remains, allowing inappropriate password resets based on timing rather than authority.'
    },
    {
      code: `if (newPassword.length < 12) { throw new Error('Password too short'); } if (requestingUser.role === 'guest' || requestingUser.role === 'user') {`,
      correct: false,
      explanation: 'Password strength validation does not address authorization issues. The privilege checking remains flawed, allowing unauthorized password resets regardless of password quality.'
    }
  ]
}