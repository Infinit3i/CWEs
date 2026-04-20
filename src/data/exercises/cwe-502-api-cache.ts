import type { Exercise } from '@/data/exercises'

/**
 * CWE-502 exercise: API response cache deserialization
 * Based on caching systems that deserialize untrusted data
 */
export const cwe502ApiCache: Exercise = {
  cweId: 'CWE-502',
  name: 'Deserialization of Untrusted Data - API Response Cache',

  vulnerableFunction: `function loadCachedApiResponse(cacheKey) {
  const redis = require('redis');
  const client = redis.createClient();

  return new Promise((resolve, reject) => {
    client.get(cacheKey, (err, cachedData) => {
      if (err) {
        reject(err);
        return;
      }

      if (cachedData) {
        try {
          // Deserialize cached response object
          const responseObject = JSON.parse(cachedData);

          // Restore object methods if present
          if (responseObject.methods) {
            for (const methodName in responseObject.methods) {
              responseObject[methodName] = new Function('return ' + responseObject.methods[methodName])();
            }
          }

          resolve(responseObject);
        } catch (parseError) {
          reject(parseError);
        }
      } else {
        resolve(null);
      }
    });
  });
}`,

  vulnerableLine: `responseObject[methodName] = new Function('return ' + responseObject.methods[methodName])();`,

  options: [
    {
      code: `function loadCachedApiResponse(cacheKey) {
  const allowedKeys = ['data', 'status', 'timestamp', 'ttl'];

  return redis.get(cacheKey).then(cachedData => {
    if (!cachedData) return null;

    const responseObject = JSON.parse(cachedData);
    const sanitized = {};

    for (const key of allowedKeys) {
      if (responseObject[key] !== undefined) {
        sanitized[key] = responseObject[key];
      }
    }

    return sanitized;
  });
}`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    // Cache deserialization vulnerabilities
    {
      code: `responseObject[methodName] = new Function('return ' + responseObject.methods[methodName])();`,
      correct: false,
      explanation: 'Function constructor with cached data allows code execution. Attackers who can modify cache contents can inject JavaScript code that executes when cached responses are loaded.'
    },
    {
      code: `const responseObject = require('pickle-js').loads(cachedData);
return responseObject;`,
      correct: false,
      explanation: 'Pickle deserialization from cache enables arbitrary code execution. If cache data is compromised, malicious pickled objects can execute commands during deserialization.'
    },
    {
      code: `const responseObject = eval('(' + cachedData + ')');
return responseObject;`,
      correct: false,
      explanation: 'Direct eval() of cached data allows immediate code execution. Any JavaScript code stored in cache will be executed when the cache is read.'
    },
    {
      code: `const responseObject = JSON.parse(cachedData);
Object.setPrototypeOf(responseObject, eval(responseObject.__proto__));`,
      correct: false,
      explanation: 'JSON parsing with eval-based prototype assignment. Attackers can inject malicious prototype definitions that execute during prototype restoration.'
    },
    {
      code: `const responseObject = require('js-yaml').safeLoad(cachedData);
if (responseObject.config) {
    require(responseObject.config.moduleName);
}`,
      correct: false,
      explanation: 'YAML deserialization followed by dynamic module loading. Even safeLoad can contain references to modules that execute code when required.'
    },
    {
      code: `const responseObject = JSON.parse(cachedData);
if (responseObject.constructor) {
    responseObject.__proto__ = responseObject.constructor.prototype;
}`,
      correct: false,
      explanation: 'Prototype manipulation based on cached constructor data. Attackers can specify arbitrary constructors to pollute prototypes or execute initialization code.'
    },
    {
      code: `const responseObject = JSON.parse(cachedData, (key, value) => {
    if (key === 'callback' && typeof value === 'string') {
        return eval(value);
    }
    return value;
});`,
      correct: false,
      explanation: 'JSON reviver function with eval() allows selective code execution. Attackers can inject malicious callback functions that execute during parsing.'
    },
    {
      code: `const responseObject = JSON.parse(cachedData);
for (const prop in responseObject.globalConfig) {
    global[prop] = responseObject.globalConfig[prop];
}`,
      correct: false,
      explanation: 'Global object pollution from cached data. Attackers can modify global variables and functions, affecting the entire application runtime.'
    },
    {
      code: `const vm = require('vm');
const responseObject = vm.runInNewContext('module.exports = ' + cachedData);
return responseObject;`,
      correct: false,
      explanation: 'VM execution of cached data as code. While runInNewContext provides isolation, malicious code can still perform destructive operations within the sandbox.'
    },
    {
      code: `const responseObject = JSON.parse(cachedData);
if (responseObject.middleware) {
    app.use(eval(responseObject.middleware));
}`,
      correct: false,
      explanation: 'Cached data influencing application middleware through eval(). Attackers can inject malicious middleware code that executes on every request.'
    }
  ]
}