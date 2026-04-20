import type { Exercise } from '@/data/exercises'

export const cwe668ApiEndpoints: Exercise = {
  cweId: 'CWE-668',
  name: 'Exposure of Resource to Wrong Sphere - API Resource Access',
  language: 'PHP',

  vulnerableFunction: `function getCompanyDocument(documentId, userRole) {
  const documentService = require('./documentService');

  // Retrieve document by ID
  const document = documentService.findById(documentId);

  if (!document) {
    throw new Error('Document not found');
  }

  return {
    id: document.id,
    title: document.title,
    content: document.content,
    department: document.department
  };
}`,

  vulnerableLine: `return { id: document.id, title: document.title, content: document.content, department: document.department };`,

  options: [
    {
      code: `if (document.department !== userRole && document.accessLevel !== 'public') throw new Error('Access denied'); return document;`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    {
      code: `return { id: document.id, title: document.title, content: document.content, department: document.department };`,
      correct: false,
      explanation: 'No authorization check allows users to access documents from any department. This exposes resources to the wrong sphere based on user roles.'
    },
    {
      code: `if (userRole === 'admin') return document; return { id: document.id, title: document.title };`,
      correct: false,
      explanation: 'Role-based filtering still allows non-admin users to access document IDs and titles from unauthorized departments. Partial information disclosure remains.'
    },
    {
      code: `return { id: document.id, title: document.title.substring(0, 50), department: document.department };`,
      correct: false,
      explanation: 'Truncating content does not address the core authorization issue. Users still gain access to document metadata outside their sphere.'
    },
    {
      code: `if (document.id < 1000) return document; throw new Error('Access denied');`,
      correct: false,
      explanation: 'ID-based filtering is arbitrary and does not properly map to department authorization. This creates an incorrect sphere boundary based on document age rather than access rights.'
    },
    {
      code: `delete document.content; return document;`,
      correct: false,
      explanation: 'Removing sensitive content still exposes document existence and metadata. Similar to MITRE examples where partial access violates sphere boundaries.'
    },
    {
      code: `if (document.department.toLowerCase() === userRole.toLowerCase()) return document;`,
      correct: false,
      explanation: 'While this attempts authorization, it fails to handle public documents or cross-department access scenarios, creating an incomplete sphere boundary.'
    },
    {
      code: `return document.department === 'public' ? document : null;`,
      correct: false,
      explanation: 'Only allowing public documents ignores legitimate department-specific access. This creates an overly restrictive sphere that blocks authorized access.'
    }
  ]
}