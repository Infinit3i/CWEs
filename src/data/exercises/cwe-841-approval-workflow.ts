import type { Exercise } from '@/data/exercises'

/**
 * CWE-841: Improper Enforcement of Behavioral Workflow - Document Approval Process
 * Workflow sequence where document publication can bypass review steps
 */
export const cwe841ApprovalWorkflow: Exercise = {
  cweId: 'CWE-841',
  name: 'Improper Enforcement of Behavioral Workflow - Document Publishing',

  vulnerableFunction: `function processDocument(documentId, action, userId) {
  const document = getDocument(documentId);
  const user = getUser(userId);

  if (action === 'submit_review') {
    document.status = 'pending_review';
    document.submittedBy = userId;
    document.submittedDate = new Date();
  }

  if (action === 'approve') {
    if (user.role !== 'reviewer') {
      throw new Error('Unauthorized approval');
    }
    document.status = 'approved';
    document.approvedBy = userId;
    document.approvedDate = new Date();
  }

  if (action === 'publish') {
    document.status = 'published';
    document.publishedDate = new Date();
    notifySubscribers(document);
  }

  return updateDocument(document);
}`,

  vulnerableLine: `if (action === 'publish') {`,

  options: [
    {
      code: `if (action === 'publish' && document.status === 'approved') {`,
      correct: true,
      explanation: `Correct! Enforces the required approval workflow where documents must be approved before publication. This prevents workflow bypass where unapproved content could be published, maintaining content quality and compliance requirements.`
    },
    {
      code: `if (action === 'publish') { // No workflow validation`,
      correct: false,
      explanation: 'Classic workflow bypass from MITRE patterns. Documents can be published without review or approval, violating content governance and potentially exposing unapproved or inappropriate content.'
    },
    {
      code: `if (action === 'publish' && document.submittedDate) {`,
      correct: false,
      explanation: 'Checks submission but not approval status. Documents can be published immediately after submission without review, bypassing the critical approval workflow step.'
    },
    {
      code: `if (action === 'publish' && user.role === 'admin') {`,
      correct: false,
      explanation: 'Admin-only publishing but no approval requirement. Admins can publish any document without review workflow, creating inconsistent process enforcement and potential content issues.'
    },
    {
      code: `if (action === 'publish' && document.submittedBy !== userId) {`,
      correct: false,
      explanation: 'Prevents self-publishing but allows publishing without approval. Different users can publish others\' unapproved documents, still bypassing the review workflow requirement.'
    },
    {
      code: `if (action === 'publish' && document.status !== 'draft') {`,
      correct: false,
      explanation: 'Prevents publishing drafts but allows publishing of pending_review documents. Documents can skip from review submission directly to publication without approval workflow.'
    },
    {
      code: `if (action === 'publish' && (document.status === 'approved' || document.urgent)) {`,
      correct: false,
      explanation: 'Creates urgent bypass pathway that violates workflow consistency. Urgent documents can skip approval entirely, creating authorization loopholes and potential content quality issues.'
    },
    {
      code: `if (action === 'publish' && document.category !== 'sensitive') {`,
      correct: false,
      explanation: 'Category-based exemption violates uniform workflow enforcement. Non-sensitive documents can bypass approval, creating inconsistent process application and potential oversight gaps.'
    },
    {
      code: `if (action === 'publish') { if (document.status !== 'approved') console.warn('Publishing without approval'); `,
      correct: false,
      explanation: 'Logs warning but allows workflow bypass. Documents are published without approval while only generating warnings, failing to enforce the mandatory review sequence.'
    },
    {
      code: `if (action === 'publish' && Date.now() - document.submittedDate > 86400000) {`,
      correct: false,
      explanation: 'Auto-approval after 24 hours bypasses review workflow. Time-based publishing violates the approval requirement and can expose content that should have been rejected.'
    }
  ]
}