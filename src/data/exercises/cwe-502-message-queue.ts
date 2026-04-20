import type { Exercise } from '@/data/exercises'

/**
 * CWE-502 exercise: Message queue deserialization
 * Based on message processing systems that deserialize untrusted data
 */
export const cwe502MessageQueue: Exercise = {
  cweId: 'CWE-502',
  name: 'Deserialization of Untrusted Data - Message Queue Processing',
  language: 'Java',

  vulnerableFunction: `function processQueueMessage(messageData) {
  const crypto = require('crypto');

  try {
    // Decode message from base64
    const decodedMessage = Buffer.from(messageData, 'base64').toString('utf8');
    let message;

    // Support multiple message formats
    if (decodedMessage.startsWith('{')) {
      message = JSON.parse(decodedMessage);
    } else if (decodedMessage.includes('---')) {
      message = require('js-yaml').load(decodedMessage);
    } else {
      // Assume it's a serialized JavaScript object
      message = eval('(' + decodedMessage + ')');
    }

    // Execute message handlers if present
    if (message.handlers) {
      message.handlers.forEach(handler => {
        if (handler.type === 'function') {
          const handlerFunc = new Function('data', handler.code);
          handlerFunc(message.data);
        } else if (handler.type === 'eval') {
          eval(handler.code);
        }
      });
    }

    // Apply message transformations
    if (message.transform && message.transform.script) {
      const transformResult = eval(message.transform.script);
      message.data = transformResult;
    }

    return {
      success: true,
      processedMessage: message
    };
  } catch (error) {
    return { success: false, error: error.message };
  }
}`,

  vulnerableLine: `message = eval('(' + decodedMessage + ')');`,

  options: [
    {
      code: `function processQueueMessage(messageData) {
  const allowedMessageTypes = ['user_action', 'system_event', 'notification'];
  const allowedFields = ['type', 'timestamp', 'userId', 'data'];

  const decodedMessage = Buffer.from(messageData, 'base64').toString('utf8');

  if (!decodedMessage.startsWith('{')) {
    throw new Error('Only JSON messages are supported');
  }

  const message = JSON.parse(decodedMessage);

  if (!allowedMessageTypes.includes(message.type)) {
    throw new Error('Invalid message type');
  }

  const sanitized = {};
  for (const field of allowedFields) {
    if (message[field] !== undefined) {
      sanitized[field] = sanitizeMessageField(message[field]);
    }
  }

  return { success: true, processedMessage: sanitized };
}`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    // Message queue deserialization vulnerabilities
    {
      code: `message = eval('(' + decodedMessage + ')');`,
      correct: false,
      explanation: 'Direct eval() of message content allows arbitrary code execution. Malicious queue messages can contain JavaScript code that executes during processing.'
    },
    {
      code: `const handlerFunc = new Function('data', handler.code);
handlerFunc(message.data);`,
      correct: false,
      explanation: 'Function constructor with message-driven code allows arbitrary execution. Attackers can inject malicious handler functions through queue messages.'
    },
    {
      code: `message.handlers.forEach(handler => {
    if (handler.type === 'eval') {
        eval(handler.code);
    }
});`,
      correct: false,
      explanation: 'Message-driven eval() execution allows arbitrary code execution. Queue messages can contain malicious handler code that executes during processing.'
    },
    {
      code: `message = require('js-yaml').load(decodedMessage);`,
      correct: false,
      explanation: 'YAML.load() can execute arbitrary code through YAML constructors and tags. Malicious YAML messages can contain executable code disguised as data.'
    },
    {
      code: `if (message.transform && message.transform.script) {
    const transformResult = eval(message.transform.script);
    message.data = transformResult;
}`,
      correct: false,
      explanation: 'Message transformation through eval() allows code execution. Attackers can inject malicious transformation scripts in queue messages.'
    },
    {
      code: `const deserializer = require('v8');
message = deserializer.deserialize(Buffer.from(decodedMessage, 'hex'));`,
      correct: false,
      explanation: 'V8 deserialization allows code execution through malicious serialized objects. V8 can deserialize objects with executable constructors or prototype methods.'
    },
    {
      code: `message = JSON.parse(decodedMessage, (key, value) => {
    if (key === 'callback' && typeof value === 'string') {
        return eval(value);
    }
    return value;
});`,
      correct: false,
      explanation: 'JSON.parse reviver function with eval() allows selective code execution. Messages can contain callback properties that execute during parsing.'
    },
    {
      code: `const vm = require('vm');
message = vm.runInThisContext('(' + decodedMessage + ')');`,
      correct: false,
      explanation: 'VM execution of message data as code. runInThisContext can access the global scope, allowing malicious messages to affect the entire application.'
    },
    {
      code: `message = JSON.parse(decodedMessage);
if (message.globalUpdates) {
    Object.assign(global, message.globalUpdates);
}`,
      correct: false,
      explanation: 'Global object pollution from message data. Queue messages can inject properties into the global namespace, affecting application behavior.'
    },
    {
      code: `message = require('pickle-js').loads(Buffer.from(decodedMessage, 'base64'));
if (message.plugins) {
    message.plugins.forEach(plugin => require(plugin));
}`,
      correct: false,
      explanation: 'Pickle deserialization with dynamic module loading. Both pickle deserialization and require() of message-specified modules allow arbitrary code execution.'
    }
  ]
}