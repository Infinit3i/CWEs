import type { Exercise } from '@/data/exercises'

export const cwe732CloudStorage: Exercise = {
  cweId: 'CWE-732',
  name: 'Incorrect Permission Assignment - Cloud Storage ACL',
  language: 'C',

  vulnerableFunction: `function deployWebAssets() {
  const aws = require('aws-sdk');
  const s3 = new aws.S3();

  const params = {
    Bucket: 'company-assets',
    Key: 'config/database-credentials.json',
    Body: JSON.stringify({host: 'db.company.com', user: 'admin', pass: 'secret123'}),
    ACL: 'public-read'
  };

  return s3.upload(params).promise();
}`,

  vulnerableLine: `ACL: 'public-read'`,

  options: [
    {
      code: `ACL: 'private'`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    {
      code: `ACL: 'public-read'`,
      correct: false,
      explanation: 'Public read access allows anyone on the internet to download database credentials. This is a critical security exposure.'
    },
    {
      code: `ACL: 'public-read-write'`,
      correct: false,
      explanation: 'Extremely dangerous - allows anyone to read or modify the credentials file. From MITRE cloud storage examples of unrestricted access.'
    },
    {
      code: `ACL: 'authenticated-read'`,
      correct: false,
      explanation: 'Allows any authenticated AWS user to read the credentials. Still too permissive for sensitive database configuration.'
    },
    {
      code: `ACL: 'bucket-owner-read'`,
      correct: false,
      explanation: 'While more restrictive, this still allows broader access than necessary. Database credentials should be private to the specific application.'
    },
    {
      code: `ACL: 'bucket-owner-full-control'`,
      correct: false,
      explanation: 'Similar to MITRE examples, this grants excessive permissions. The bucket owner may be different from the application needing access.'
    },
    {
      code: `// Remove ACL parameter to use default`,
      correct: false,
      explanation: 'Without explicit ACL, AWS uses the bucket policy default, which may be overly permissive depending on bucket configuration.'
    },
    {
      code: `ACL: 'aws-exec-read'`,
      correct: false,
      explanation: 'Grants read access to AWS EC2 instances globally. Database credentials should not be accessible to arbitrary EC2 instances.'
    }
  ]
}