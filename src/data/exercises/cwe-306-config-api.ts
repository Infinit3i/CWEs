import type { Exercise } from '@/data/exercises'

/**
 * CWE-306: Missing Authentication for System Configuration API
 * Infrastructure scenario: Configuration management endpoint without access control
 */
export const cwe306ConfigApi: Exercise = {
  cweId: 'CWE-306',
  name: 'Missing Authentication - System Configuration',

  vulnerableFunction: `class ConfigurationController {
  async updateSystemConfig(req: Request, res: Response) {
    const { configKey, configValue, environment } = req.body;

    // Validate configuration parameters
    if (!configKey || configValue === undefined) {
      return res.status(400).json({ error: 'Configuration key and value required' });
    }

    const allowedKeys = ['debug_mode', 'maintenance_window', 'api_rate_limit', 'feature_flags'];
    if (!allowedKeys.includes(configKey)) {
      return res.status(400).json({ error: 'Invalid configuration key' });
    }

    // Update system configuration
    await SystemConfig.update({
      key: configKey,
      value: configValue,
      environment: environment || 'production',
      updatedAt: new Date()
    });

    // Apply configuration changes
    await this.reloadSystemConfiguration();

    res.status(200).json({
      message: 'Configuration updated successfully',
      key: configKey,
      value: configValue,
      environment
    });
  }
}`,

  vulnerableLine: `async updateSystemConfig(req: Request, res: Response) {`,

  options: [
    {
      code: `async updateSystemConfig(req: Request, res: Response) { const user = await this.authenticateAdmin(req); if (!user || !user.hasPermission('SYSTEM_CONFIG')) { return res.status(403).json({ error: 'Admin privileges required' }); }`,
      correct: true,
      explanation: `Correct! System configuration changes require administrative authentication and authorization. Unauthenticated configuration access allows attackers to modify critical system behavior and security settings.`
    },
    {
      code: `async updateSystemConfig(req: Request, res: Response) {`,
      correct: false,
      explanation: 'From MITRE: Missing authentication for sensitive system operations allows unauthorized configuration changes. This can compromise system security, availability, and functionality.'
    },
    {
      code: `async updateSystemConfig(req: Request, res: Response) { if (req.body.environment === 'production' && !req.headers['x-prod-key']) { return res.status(403).json({ error: 'Production key required' }); }`,
      correct: false,
      explanation: 'Conditional header checking without validation provides no security. Any value in the x-prod-key header would satisfy this check for production configuration changes.'
    },
    {
      code: `async updateSystemConfig(req: Request, res: Response) { const configHash = req.headers['x-config-hash']; if (!configHash) { return res.status(401).json({ error: 'Configuration hash required' }); }`,
      correct: false,
      explanation: 'Requiring a hash header without validation is meaningless. Any string value would satisfy this requirement while providing no authentication or integrity checking.'
    },
    {
      code: `async updateSystemConfig(req: Request, res: Response) { if (req.method !== 'POST' || !req.headers['content-type']?.includes('json')) { return res.status(400).json({ error: 'Invalid request format' }); }`,
      correct: false,
      explanation: 'Request format validation does not provide authentication. This only checks the HTTP method and content type but allows anyone to make properly formatted configuration changes.'
    },
    {
      code: `async updateSystemConfig(req: Request, res: Response) { const sourceIp = req.ip; if (!this.isManagementNetwork(sourceIp)) { return res.status(403).json({ error: 'Access denied from this network' }); }`,
      correct: false,
      explanation: 'Network-based access control is not user authentication. Management network access does not verify individual user identity or specific administrative privileges.'
    },
    {
      code: `async updateSystemConfig(req: Request, res: Response) { if (!req.body.reason) { return res.status(400).json({ error: 'Change reason required' }); }`,
      correct: false,
      explanation: 'Requiring a reason field improves audit trails but provides no authentication. Any user can provide a reason while making unauthorized configuration changes.'
    },
    {
      code: `async updateSystemConfig(req: Request, res: Response) { const configToken = req.query.token; if (configToken !== process.env.CONFIG_SECRET) { return res.status(401).json({ error: 'Invalid configuration token' }); }`,
      correct: false,
      explanation: 'Shared secret tokens provide weak authentication for multi-admin systems. A single leaked token compromises all configuration access without user accountability.'
    }
  ]
}