import type { Exercise } from '@/data/exercises'

/**
 * CWE-502 exercise: Backup data restoration
 * Based on backup/restore systems that deserialize untrusted data
 */
export const cwe502BackupRestore: Exercise = {
  cweId: 'CWE-502',
  name: 'Deserialization of Untrusted Data - Database Backup Restoration',

  vulnerableFunction: `function restoreFromBackup(backupData, restoreOptions) {
  const crypto = require('crypto');

  try {
    // Decompress backup data
    const decompressed = require('zlib').inflateSync(Buffer.from(backupData, 'base64'));
    const backupJson = decompressed.toString('utf8');

    // Parse backup metadata and data
    const backup = JSON.parse(backupJson);

    // Validate backup integrity (simple checksum)
    const calculatedHash = crypto.createHash('md5').update(backup.data).digest('hex');
    if (calculatedHash !== backup.checksum) {
      throw new Error('Backup integrity check failed');
    }

    // Deserialize data objects with custom deserializer
    const restoredData = backup.data.map(item => {
      if (item.type === 'serialized') {
        return eval('(' + item.content + ')');
      } else if (item.type === 'compressed_object') {
        return require('v8').deserialize(Buffer.from(item.content, 'hex'));
      }
      return JSON.parse(item.content);
    });

    // Apply restoration hooks if present
    if (backup.hooks && backup.hooks.postRestore) {
      eval(backup.hooks.postRestore);
    }

    return {
      success: true,
      restoredItems: restoredData.length,
      data: restoredData
    };
  } catch (error) {
    return { success: false, error: error.message };
  }
}`,

  vulnerableLine: `return eval('(' + item.content + ')');`,

  options: [
    {
      code: `function restoreFromBackup(backupData, restoreOptions) {
  const hmac = crypto.createHmac('sha256', process.env.BACKUP_SECRET);
  const [payload, signature] = backupData.split('.');

  if (hmac.update(payload).digest('hex') !== signature) {
    throw new Error('Backup signature verification failed');
  }

  const backup = JSON.parse(Buffer.from(payload, 'base64').toString());
  const allowedFields = ['id', 'name', 'data', 'timestamp'];

  const restoredData = backup.items.map(item => {
    const sanitized = {};
    for (const field of allowedFields) {
      if (item[field] !== undefined) {
        sanitized[field] = sanitizeValue(item[field]);
      }
    }
    return sanitized;
  });

  return { success: true, data: restoredData };
}`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    // Backup restoration deserialization vulnerabilities
    {
      code: `return eval('(' + item.content + ')');`,
      correct: false,
      explanation: 'Direct eval() of backup content allows arbitrary code execution. Malicious backup files can contain JavaScript code that executes during restoration.'
    },
    {
      code: `return require('v8').deserialize(Buffer.from(item.content, 'hex'));`,
      correct: false,
      explanation: 'V8 deserialization of untrusted data enables code execution. Malicious V8 serialized objects can contain executable code or constructor functions that run during deserialization.'
    },
    {
      code: `if (backup.hooks && backup.hooks.postRestore) {
    eval(backup.hooks.postRestore);
}`,
      correct: false,
      explanation: 'Backup-driven hook execution allows arbitrary code execution. Attackers can inject malicious JavaScript code in backup hook properties that execute after restoration.'
    },
    {
      code: `const restoredObject = require('pickle-js').loads(Buffer.from(item.content, 'base64'));
return restoredObject;`,
      correct: false,
      explanation: 'Pickle deserialization allows arbitrary code execution. Malicious pickle data can contain embedded Python/JavaScript code that executes during the unpickling process.'
    },
    {
      code: `const backup = JSON.parse(backupJson);
if (backup.globalConfig) {
    Object.assign(global, backup.globalConfig);
}`,
      correct: false,
      explanation: 'Global object pollution from backup data. Attackers can inject properties into the global namespace through backup files, affecting application behavior.'
    },
    {
      code: `const vm = require('vm');
return vm.runInNewContext('module.exports = ' + item.content);`,
      correct: false,
      explanation: 'VM execution of backup content as code. Even with sandbox isolation, malicious code in backup data can perform destructive operations or escape the sandbox.'
    },
    {
      code: `const restoredObject = new Function('return ' + item.content)();
if (restoredObject.constructor) {
    Object.setPrototypeOf(restoredObject, restoredObject.constructor.prototype);
}`,
      correct: false,
      explanation: 'Function constructor with prototype manipulation allows code execution and prototype pollution. Backup data can contain constructor functions and prototype definitions.'
    },
    {
      code: `const backup = require('js-yaml').load(backupJson);
backup.plugins.forEach(plugin => require(plugin.path));`,
      correct: false,
      explanation: 'YAML deserialization with dynamic module loading. YAML can contain constructor tags and the plugin loading allows arbitrary module execution from backup data.'
    },
    {
      code: `const backup = JSON.parse(backupJson, (key, value) => {
    if (key === 'code' && typeof value === 'string') {
        return new Function(value);
    }
    return value;
});`,
      correct: false,
      explanation: 'JSON.parse reviver function creating executable code. Backup files can contain code properties that become executable functions during parsing.'
    },
    {
      code: `const restoredData = backup.data.map(item => {
    const obj = JSON.parse(item.content);
    for (const method in item.methods) {
        obj[method] = eval(item.methods[method]);
    }
    return obj;
});`,
      correct: false,
      explanation: 'Method injection through eval() during restoration. Backup data can contain malicious method definitions that execute when objects are reconstructed.'
    }
  ]
}