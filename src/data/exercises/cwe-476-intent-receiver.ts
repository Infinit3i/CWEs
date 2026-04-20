import type { Exercise } from '@/data/exercises'

/**
 * CWE-476 exercise - Android Intent Receiver
 * Based on MITRE Android example for NULL pointer dereference
 */
export const cwe476IntentReceiver: Exercise = {
  cweId: 'CWE-476',
  name: 'NULL Pointer Dereference - Intent Receiver',

  vulnerableFunction: `function onReceiveIntent(context, intent) {
  // Extract URL from intent data
  const urlToOpen = intent.getStringExtra("URLToOpen");

  // Get URL length for validation
  const urlLength = urlToOpen.length; // Potential null dereference

  if (urlLength > 0 && urlLength < 2048) {
    openURL(urlToOpen);
  }
}`,

  vulnerableLine: `const urlLength = urlToOpen.length;`,

  options: [
    {
      code: `const urlToOpen = intent.getStringExtra("URLToOpen"); if (urlToOpen === null || urlToOpen === undefined) { console.log("No URL provided in intent"); return; } const urlLength = urlToOpen.length;`,
      correct: true,
      explanation: `Correct! This validates the intent data exists before accessing properties. The MITRE example shows "Missing intent data returns null; calling length() on null causes application crash" when the URLToOpen extra is not provided.`
    },
    {
      code: `public void onReceive(Context context, Intent intent) { String URL = intent.getStringExtra("URLToOpen"); int length = URL.length(); }`,
      correct: false,
      explanation: 'Direct from MITRE: "Missing intent data returns null" but the code proceeds to call length() on NULL, causing a NullPointerException and application crash when the URLToOpen extra is not provided.'
    },
    {
      code: `const urlToOpen = intent.getStringExtra("URLToOpen"); try { const urlLength = urlToOpen.length; } catch (error) { console.log("Error processing URL"); }`,
      correct: false,
      explanation: 'Exception handling cannot prevent NULL dereference crashes in the context where they occur. The error happens at the property access level before exceptions can be properly caught.'
    },
    {
      code: `const urlToOpen = intent.getStringExtra("URLToOpen"); if (intent.hasExtra("URLToOpen")) { const urlLength = urlToOpen.length; }`,
      correct: false,
      explanation: 'Checking if the extra exists is insufficient because the extra can be present but contain a NULL value, which would still cause a dereference error when accessing length.'
    },
    {
      code: `const urlToOpen = intent.getStringExtra("URLToOpen") || ""; const urlLength = urlToOpen.length;`,
      correct: false,
      explanation: 'While this prevents the crash by providing a default empty string, it may not be the intended behavior and could cause unexpected application flow when no URL is actually provided.'
    },
    {
      code: `let urlToOpen; setTimeout(() => { urlToOpen = intent.getStringExtra("URLToOpen"); const urlLength = urlToOpen.length; }, 100);`,
      correct: false,
      explanation: 'Asynchronous processing does not solve NULL dereference issues and may create timing problems. The intent data availability does not change with time delays.'
    },
    {
      code: `const urlToOpen = intent.getStringExtra("URLToOpen"); if (typeof urlToOpen === 'string') { const urlLength = urlToOpen.length; }`,
      correct: false,
      explanation: 'Type checking is good practice but may not catch all NULL cases depending on the platform. Some implementations might return NULL which could have unexpected typeof results.'
    },
    {
      code: `const urlToOpen = intent.getStringExtra("URLToOpen"); const isEmpty = urlToOpen.trim().length === 0; if (!isEmpty) { const urlLength = urlToOpen.length; }`,
      correct: false,
      explanation: 'Attempting to call trim() on a NULL value will cause the same dereference error we are trying to prevent, just moving the crash to a different location in the code.'
    },
    {
      code: `const urlToOpen = intent.getStringExtra("URLToOpen"); if (urlToOpen.constructor === String) { const urlLength = urlToOpen.length; }`,
      correct: false,
      explanation: 'Checking the constructor property will fail when urlToOpen is NULL because accessing any property of NULL causes a dereference error before the constructor check can complete.'
    },
    {
      code: `const urlToOpen = intent.getStringExtra("URLToOpen"); const urlLength = urlToOpen && urlToOpen.length ? urlToOpen.length : 0;`,
      correct: false,
      explanation: 'While this prevents the crash using short-circuit evaluation, it is less explicit than proper null checking and the ternary operator makes the code less readable and maintainable.'
    }
  ]
}