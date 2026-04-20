import type { Exercise } from '@/data/exercises'

/**
 * CWE-209: Information Exposure Through External Service Errors
 * Scenario: API gateway exposing third-party service integration details
 * Based on MITRE demonstrative examples showing service integration error leakage
 */
export const cwe209ExternalService: Exercise = {
  cweId: 'CWE-209',
  name: 'Information Exposure - External Service Errors',

  vulnerableFunction: `app.post('/api/send-notification', authenticateUser, async (req, res) => {
  try {
    const { message, recipients, channel } = req.body;
    
    // Validate input
    if (!message || !recipients || !Array.isArray(recipients)) {
      return res.status(400).json({ error: 'Invalid notification request' });
    }
    
    let result;
    
    switch (channel) {
      case 'email':
        result = await sendEmailNotification(message, recipients);
        break;
      case 'sms':
        result = await sendSMSNotification(message, recipients);
        break;
      case 'push':
        result = await sendPushNotification(message, recipients);
        break;
      case 'slack':
        result = await sendSlackNotification(message, recipients);
        break;
      default:
        return res.status(400).json({ error: 'Unsupported notification channel' });
    }
    
    res.json({
      message: 'Notification sent successfully',
      deliveredTo: result.successful,
      failed: result.failed
    });
    
  } catch (error) {
    console.error('Notification service error:', error);
    
    // Return detailed third-party service error information
    res.status(500).json({
      error: 'Notification delivery failed',
      service: error.service,
      serviceError: {
        message: error.message,
        code: error.code,
        statusCode: error.statusCode,
        response: error.response,
        requestId: error.requestId,
        apiKey: error.config?.apiKey,
        endpoint: error.config?.url,
        headers: error.config?.headers,
        timeout: error.config?.timeout,
        retryAttempts: error.config?.retryAttempts
      },
      providerInfo: {
        emailProvider: 'SendGrid',
        emailApiKey: process.env.SENDGRID_API_KEY,
        smsProvider: 'Twilio',
        twilioAccountSid: process.env.TWILIO_ACCOUNT_SID,
        twilioAuthToken: process.env.TWILIO_AUTH_TOKEN,
        pushProvider: 'Firebase',
        firebaseServerKey: process.env.FIREBASE_SERVER_KEY,
        slackProvider: 'Slack API',
        slackBotToken: process.env.SLACK_BOT_TOKEN,
        slackWebhookUrl: process.env.SLACK_WEBHOOK_URL
      },
      requestDetails: {
        originalMessage: message,
        targetRecipients: recipients,
        requestedChannel: channel,
        userId: req.user.id,
        userEmail: req.user.email,
        timestamp: new Date().toISOString(),
        requestId: req.headers['x-request-id'],
        userAgent: req.headers['user-agent'],
        ipAddress: req.ip
      },
      debugInfo: {
        nodeEnv: process.env.NODE_ENV,
        serverHostname: require('os').hostname(),
        processId: process.pid,
        memoryUsage: process.memoryUsage(),
        uptime: process.uptime()
      },
      troubleshooting: [
        'Verify API keys in environment variables',
        'Check service provider status pages',
        'Review rate limiting and quotas',
        'Validate webhook configurations'
      ]
    });
  }
});

async function sendEmailNotification(message, recipients) {
  try {
    const response = await fetch('https://api.sendgrid.com/v3/mail/send', {
      method: 'POST',
      headers: {
        'Authorization': \`Bearer \${process.env.SENDGRID_API_KEY}\`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        from: { email: 'noreply@company.com' },
        to: recipients.map(email => ({ email })),
        subject: 'Notification',
        content: [{ type: 'text/plain', value: message }]
      })
    });
    
    if (!response.ok) {
      const error = new Error('SendGrid API error');
      error.service = 'SendGrid';
      error.statusCode = response.status;
      error.response = await response.text();
      error.config = {
        url: 'https://api.sendgrid.com/v3/mail/send',
        apiKey: process.env.SENDGRID_API_KEY,
        headers: response.headers
      };
      throw error;
    }
    
    return { successful: recipients, failed: [] };
  } catch (error) {
    error.service = 'SendGrid';
    throw error;
  }
}`,

  vulnerableLine: `res.status(500).json({`,

  options: [
    {
      code: `// Log detailed service error securely, return generic message
const errorId = crypto.randomUUID();

console.error('External service error:', {
  errorId,
  service: error.service || 'unknown',
  statusCode: error.statusCode,
  userId: req.user?.id,
  channel: channel,
  recipientCount: recipients?.length,
  timestamp: new Date().toISOString(),
  // Avoid logging sensitive data like API keys or message content
  errorType: error.constructor.name
});

// Return generic error without exposing service details
res.status(500).json({
  error: 'Notification service temporarily unavailable',
  errorId: errorId,
  message: 'Please try again later or contact support if the problem persists'
});`,
      correct: true,
      explanation: `Correct! This prevents information exposure by logging essential debugging information securely on the server while returning only a generic error message to the client. The error ID enables correlation between user reports and server logs without exposing sensitive service provider details, API keys, configuration information, or system architecture that attackers could use to compromise third-party integrations or plan targeted attacks.`
    },
    // Real MITRE demonstrative examples as wrong answers
    {
      code: `res.status(500).json({
  error: 'Notification delivery failed',
  serviceError: {
    message: error.message,
    code: error.code,
    endpoint: error.config?.url,
    apiKey: error.config?.apiKey
  },
  providerInfo: {
    emailProvider: 'SendGrid',
    emailApiKey: process.env.SENDGRID_API_KEY,
    twilioAuthToken: process.env.TWILIO_AUTH_TOKEN,
    firebaseServerKey: process.env.FIREBASE_SERVER_KEY
  }
});`,
      correct: false,
      explanation: 'Direct from MITRE CWE-209: Exposing detailed third-party service errors reveals critical integration secrets including API keys, authentication tokens, service endpoints, and provider information. Attackers can use these credentials to impersonate the application or abuse the third-party services.'
    },
    {
      code: `res.status(500).json({
  error: 'External service error',
  provider: error.service,
  apiResponse: error.response,
  endpoint: error.config?.url,
  statusCode: error.statusCode
});`,
      correct: false,
      explanation: 'Service integration details from MITRE examples expose API endpoints, response data, and provider information that can help attackers understand the application\'s external dependencies and potentially target those services.'
    },
    {
      code: `res.status(500).json({
  error: 'Service unavailable',
  details: {
    requestId: error.requestId,
    retryAttempts: error.config?.retryAttempts,
    timeout: error.config?.timeout,
    headers: error.config?.headers
  }
});`,
      correct: false,
      explanation: 'Service configuration details reveal operational parameters including retry logic, timeout values, and request headers that can help attackers understand service behavior and plan denial-of-service or rate-limiting attacks.'
    },
    {
      code: `const sanitizedError = error.message.replace(/key_[a-zA-Z0-9]+/g, 'key_[REDACTED]');
res.status(500).json({
  error: 'Service error',
  details: sanitizedError,
  provider: error.service,
  endpoint: new URL(error.config?.url).hostname
});`,
      correct: false,
      explanation: 'Simple credential redaction is insufficient when other sensitive information like service providers and endpoint hostnames are still exposed. This information helps attackers identify integration points and plan targeted attacks.'
    },
    {
      code: `if (error.statusCode === 401) {
  res.status(500).json({
    error: 'Authentication failed with external service',
    service: error.service,
    suggestion: 'Check API key configuration'
  });
} else {
  res.status(500).json({ error: 'External service error' });
}`,
      correct: false,
      explanation: 'Authentication error details reveal specific service integration failures and suggest configuration issues. This information can help attackers identify misconfigured services or authentication weaknesses.'
    },
    {
      code: `res.status(500).json({
  error: 'Notification failed',
  serviceType: error.service?.toLowerCase(),
  errorCategory: error.code ? 'client_error' : 'network_error',
  retryRecommended: error.statusCode >= 500
});`,
      correct: false,
      explanation: 'Service categorization and error classification still provide valuable reconnaissance information about external dependencies, error handling logic, and system behavior that can aid in attack planning.'
    },
    {
      code: `const errorHash = crypto.createHash('md5').update(error.message).digest('hex');
res.status(500).json({
  error: 'Service communication failed',
  errorFingerprint: errorHash,
  service: error.service
});`,
      correct: false,
      explanation: 'Error fingerprinting combined with service identification can still provide attackers with information about specific failures and external dependencies, enabling targeted reconnaissance.'
    },
    {
      code: `console.log('Service error details:', {
  service: error.service,
  endpoint: error.config?.url,
  apiKey: error.config?.apiKey?.substring(0, 5) + '***'
});
res.status(500).json({ error: 'Notification service error' });`,
      correct: false,
      explanation: 'While the response is generic, logging partial API keys and endpoints to console can expose sensitive information through log files, especially if logs are accessible or if there are log injection vulnerabilities.'
    },
    {
      code: `res.status(500).json({
  error: 'Service integration error',
  debug: process.env.NODE_ENV === 'development' ? {
    service: error.service,
    statusCode: error.statusCode,
    message: error.message
  } : undefined
});`,
      correct: false,
      explanation: 'Environment-conditional debugging can expose sensitive service integration details if the environment is misconfigured, or if attackers can determine the deployment environment through other reconnaissance methods.'
    }
  ]
}
