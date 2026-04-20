import type { Exercise } from '@/data/exercises'

/**
 * CWE-476 exercise - HTTP Response Handling
 * Based on MITRE Go example with deferred operations on nil response
 */
export const cwe476HttpResponse: Exercise = {
  cweId: 'CWE-476',
  name: 'NULL Pointer Dereference - HTTP Response Handling',

  vulnerableFunction: `function handleRequest(client, request) {
  let response = null;

  // Defer cleanup - evaluated immediately!
  const cleanup = () => {
    if (response && response.body) {
      response.body.close(); // Potential null dereference
    }
  };

  try {
    response = client.do(request);
  } catch (error) {
    cleanup();
    return null;
  }

  cleanup();
  return response;
}`,

  vulnerableLine: `response.body.close();`,

  options: [
    {
      code: `const cleanup = () => { if (response !== null && response !== undefined && response.body) { response.body.close(); } }; try { response = client.do(request); } catch (error) { cleanup(); return null; }`,
      correct: true,
      explanation: `Use proper cryptographic functions`
    },
    {
      code: `func HandleRequest(client http.Client, request *http.Request) (*http.Response, error) { response, err := client.Do(request); defer response.Body.Close(); if err != nil { return nil, err; } }`,
      correct: false,
      explanation: '"The defer statement executes before error checking. A nil response causes a panic" because defer evaluates immediately, accessing Body.Close() on a nil response when client.Do() fails.'
    },
    {
      code: `const cleanup = () => { try { response.body.close(); } catch (e) { console.log("Cleanup failed"); } }; response = client.do(request);`,
      correct: false,
      explanation: 'Exception handling around the dereference cannot prevent the NULL pointer access crash. The error occurs at the memory access level before exceptions can be properly handled.'
    },
    {
      code: `const cleanup = () => { setTimeout(() => { response.body.close(); }, 10); }; response = client.do(request);`,
      correct: false,
      explanation: 'Delaying the operation does not prevent NULL dereference. If response is NULL, waiting will not change it to a valid object, and the crash will just occur later.'
    },
    {
      code: `const cleanup = () => { if (typeof response === 'object') { response.body.close(); } }; response = client.do(request);`,
      correct: false,
      explanation: 'Type checking is insufficient because NULL is also of type "object" in JavaScript. This check would still allow NULL values to pass through and cause dereference errors.'
    },
    {
      code: `const cleanup = () => { const hasBody = response.hasOwnProperty('body'); if (hasBody) { response.body.close(); } }; response = client.do(request);`,
      correct: false,
      explanation: 'Calling hasOwnProperty() on a NULL response will cause a dereference error before the property check can complete, moving the crash to an earlier location.'
    },
    {
      code: `const cleanup = () => { if (response && response.body && response.body.close) { response.body.close(); } }; response = client.do(request);`,
      correct: false,
      explanation: 'While this prevents the crash using proper null checking, it is less explicit than the correct solution and checking for the existence of the close method is redundant if we know the API structure.'
    },
    {
      code: `const cleanup = () => { const responseJson = JSON.stringify(response); if (responseJson !== 'null') { response.body.close(); } }; response = client.do(request);`,
      correct: false,
      explanation: 'JSON.stringify() will convert null to the string "null", but then accessing response.body will still cause a dereference error on the original null value.'
    },
    {
      code: `const cleanup = () => { if (response.constructor === Object) { response.body.close(); } }; response = client.do(request);`,
      correct: false,
      explanation: 'Checking the constructor property will throw an error when attempting to access the constructor property of a NULL value, causing the same type of crash we are trying to prevent.'
    },
    {
      code: `let isResponseValid = false; const cleanup = () => { if (isResponseValid) { response.body.close(); } }; response = client.do(request); isResponseValid = true;`,
      correct: false,
      explanation: 'Using a separate flag does not validate the actual response object. If client.do() returns null, setting isResponseValid to true does not change the null response to a valid object.'
    }
  ]
}