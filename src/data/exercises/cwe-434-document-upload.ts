import type { Exercise } from '@/data/exercises'

/**
 * CWE-434 exercise - Document Upload
 * Based on MITRE Java servlet vulnerability with path traversal
 */
export const cwe434DocumentUpload: Exercise = {
  cweId: 'CWE-434',
  name: 'Unrestricted Upload - Document Upload',
  language: 'PHP',

  vulnerableFunction: `@PostMapping("/upload/document")
public ResponseEntity<?> uploadDocument(@RequestParam("file") MultipartFile file) {
    String filename = file.getOriginalFilename();
    String uploadPath = uploadLocation + filename;

    try {
        file.transferTo(new File(uploadPath));
        return ResponseEntity.ok("Document uploaded successfully");
    } catch (IOException e) {
        return ResponseEntity.status(500).body("Upload failed");
    }
}`,

  vulnerableLine: `String uploadPath = uploadLocation + filename;`,

  options: [
    {
      code: `String[] allowedExts = {".pdf", ".doc", ".docx", ".txt"}; String ext = FilenameUtils.getExtension(filename).toLowerCase(); if (!Arrays.asList(allowedExts).contains("." + ext)) { throw new IllegalArgumentException("File type not allowed"); } String safeFilename = UUID.randomUUID().toString() + "." + ext; String uploadPath = Paths.get(uploadLocation, safeFilename).toString();`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    {
      code: `String filename = pLine.substring(pLine.lastIndexOf("\\\\"), pLine.lastIndexOf("\\")); BufferedWriter bw = new BufferedWriter(new FileWriter(uploadLocation+filename, true));`,
      correct: false,
      explanation: 'Extracts filename from HTTP header without validation, allowing both executable file uploads (.asp, .jsp) and path traversal sequences ("../") to write files outside the intended directory.'
    },
    {
      code: `if (filename.endsWith(".pdf") || filename.endsWith(".doc")) { String uploadPath = uploadLocation + filename; file.transferTo(new File(uploadPath)); }`,
      correct: false,
      explanation: 'Double extensions like "malicious.jsp.pdf" bypass this check as the server processes the inner .jsp extension while the outer .pdf satisfies the validation.'
    },
    {
      code: `if (!filename.contains("../")) { String uploadPath = uploadLocation + filename; file.transferTo(new File(uploadPath)); }`,
      correct: false,
      explanation: 'MITRE vulnerability: This misses encoded traversal sequences like "%2e%2e%2f" and absolute paths. Also allows executable files like "shell.jsp" without path traversal.'
    },
    {
      code: `String sanitized = filename.replaceAll("[^a-zA-Z0-9._-]", ""); String uploadPath = uploadLocation + sanitized;`,
      correct: false,
      explanation: 'Character filtering allows dangerous extensions like "malicious.jsp" as long as they contain only allowed characters. Does not validate file type or content.'
    },
    {
      code: `if (file.getSize() > 0 && file.getSize() < 10485760) { String uploadPath = uploadLocation + filename; file.transferTo(new File(uploadPath)); }`,
      correct: false,
      explanation: 'Size validation is good practice but does not prevent executable uploads or path traversal. Small JSP shells can be very effective within size limits.'
    },
    {
      code: `if (file.getContentType().equals("application/pdf")) { String uploadPath = uploadLocation + filename; file.transferTo(new File(uploadPath)); }`,
      correct: false,
      explanation: 'MIME type validation alone can be bypassed by crafting files with PDF MIME types but executable extensions, or by manipulating the Content-Type header in the request.'
    },
    {
      code: `String basename = FilenameUtils.getBaseName(filename); String extension = FilenameUtils.getExtension(filename); String uploadPath = uploadLocation + basename + "." + extension;`,
      correct: false,
      explanation: 'Path parsing alone does not validate file types. This still allows uploading "malicious.jsp" files and does not prevent execution of server-side scripts.'
    },
    {
      code: `if (!filename.isEmpty() && filename.length() < 255) { String uploadPath = uploadLocation + filename; file.transferTo(new File(uploadPath)); }`,
      correct: false,
      explanation: 'Basic length validation provides no protection against malicious file types or path traversal attacks. Any reasonably-named executable file passes this check.'
    },
    {
      code: `String lowercase = filename.toLowerCase(); String uploadPath = uploadLocation + lowercase; file.transferTo(new File(uploadPath));`,
      correct: false,
      explanation: 'Case normalization alone does not prevent execution. "malicious.jsp" in lowercase is still a dangerous server-side script that can execute arbitrary code.'
    }
  ]
}