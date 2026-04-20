import type { Exercise } from '@/data/exercises'

/**
 * CWE-306: Missing Authentication for File Upload Service
 * Enterprise scenario: Document management system with unprotected upload endpoint
 */
export const cwe306FileUpload: Exercise = {
  cweId: 'CWE-306',
  name: 'Missing Authentication - File Upload Service',

  vulnerableFunction: `class DocumentService {
  async uploadDocument(req: Request, res: Response) {
    const file = req.file;
    const { category, confidential } = req.body;

    if (!file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const document = await Document.create({
      filename: file.originalname,
      path: file.path,
      size: file.size,
      category: category || 'general',
      confidential: confidential === 'true',
      uploadedAt: new Date()
    });

    // Move to appropriate storage based on confidentiality
    if (document.confidential) {
      await this.moveToSecureStorage(document);
    }

    res.status(201).json({
      message: 'Document uploaded successfully',
      documentId: document.id,
      filename: document.filename
    });
  }
}`,

  vulnerableLine: `async uploadDocument(req: Request, res: Response) {`,

  options: [
    {
      code: `async uploadDocument(req: Request, res: Response) { const user = await this.authenticateUser(req); if (!user) { return res.status(401).json({ error: 'Authentication required' }); }`,
      correct: true,
      explanation: `Correct! File upload endpoints must authenticate users before allowing document storage. Unauthenticated uploads can lead to storage abuse, malware injection, and unauthorized content hosting.`
    },
    {
      code: `async uploadDocument(req: Request, res: Response) {`,
      correct: false,
      explanation: 'From MITRE: Missing authentication allows anyone to upload files to the system. This enables storage abuse, malware hosting, and potential system compromise through uploaded content.'
    },
    {
      code: `async uploadDocument(req: Request, res: Response) { if (!req.headers['content-length']) { return res.status(400).json({ error: 'Content-Length required' }); }`,
      correct: false,
      explanation: 'Content-Length validation does not provide authentication. Any request with a Content-Length header would bypass this check while remaining unauthenticated.'
    },
    {
      code: `async uploadDocument(req: Request, res: Response) { const referer = req.headers.referer; if (!referer || !referer.includes('company.com')) { return res.status(403).json({ error: 'Invalid referer' }); }`,
      correct: false,
      explanation: 'Referer header validation is not authentication and can be spoofed. This provides no verification of user identity or authorization to upload files.'
    },
    {
      code: `async uploadDocument(req: Request, res: Response) { if (req.body.category === 'confidential' && !req.headers['x-admin-token']) { return res.status(403).json({ error: 'Admin token required for confidential uploads' }); }`,
      correct: false,
      explanation: 'Conditional header checking without token validation provides no security. Any value in the x-admin-token header would satisfy this check for confidential uploads.'
    },
    {
      code: `async uploadDocument(req: Request, res: Response) { const clientIp = req.ip; if (!this.isInternalIP(clientIp)) { return res.status(403).json({ error: 'External access denied' }); }`,
      correct: false,
      explanation: 'IP-based restrictions are not authentication. Internal network access does not verify user identity, and IP addresses can be spoofed or proxied.'
    },
    {
      code: `async uploadDocument(req: Request, res: Response) { const uploadKey = req.headers['x-upload-key']; if (uploadKey !== process.env.UPLOAD_SECRET) { return res.status(401).json({ error: 'Invalid upload key' }); }`,
      correct: false,
      explanation: 'Shared secret authentication is weak for multi-user systems. A single leaked key compromises all uploads, and there is no user accountability or authorization granularity.'
    },
    {
      code: `async uploadDocument(req: Request, res: Response) { if (!req.body.username) { return res.status(400).json({ error: 'Username required' }); }`,
      correct: false,
      explanation: 'Requiring a username field without authentication allows users to impersonate others. Any username can be provided without verification of identity.'
    }
  ]
}