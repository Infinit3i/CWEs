import type { Exercise } from '@/data/exercises'

/**
 * CWE-119 exercise: String copy buffer overflow
 * Based on unsafe string operations that exceed buffer boundaries
 */
export const cwe119StringCopy: Exercise = {
  cweId: 'CWE-119',
  name: 'Memory Buffer Bounds - User Input String Copy Operations',
  language: 'C',

  vulnerableFunction: `#include <stdio.h>
#include <string.h>
#include <time.h>

typedef struct {
    char category[32];
    char content[256];
    char metadata[64];
} ProcessedData;

int process_user_input(char* user_input, char* category, ProcessedData* result) {
    const int MAX_INPUT_LENGTH = 256;

    // Validate input length
    if (strlen(user_input) > MAX_INPUT_LENGTH) {
        return -1; // Input too long
    }

    // Clear the structure
    memset(result, 0, sizeof(ProcessedData));

    // Copy category (could be longer than buffer)
    strcpy(result->category, category);

    // Copy user input
    strcpy(result->content, user_input);

    // Generate metadata (timestamp + category + content length)
    time_t timestamp = time(NULL);
    sprintf(result->metadata, "%ld|%s|%zu", timestamp, category, strlen(user_input));

    return 0;
}`,

  vulnerableLine: `strcpy(result->category, category);`,

  options: [
    {
      code: `int process_user_input(char* user_input, char* category, ProcessedData* result) {
    const int MAX_CATEGORY_LENGTH = 31; // Leave space for null terminator
    const int MAX_INPUT_LENGTH = 255;   // Leave space for null terminator
    const int MAX_METADATA_LENGTH = 63; // Leave space for null terminator

    // Validate all input lengths
    if (strlen(user_input) > MAX_INPUT_LENGTH) {
        return -1; // Input too long
    }

    if (strlen(category) > MAX_CATEGORY_LENGTH) {
        return -2; // Category name too long
    }

    // Clear the structure
    memset(result, 0, sizeof(ProcessedData));

    // Safe copying with bounds checking
    strncpy(result->category, category, MAX_CATEGORY_LENGTH);
    result->category[MAX_CATEGORY_LENGTH] = '\\0'; // Ensure null termination

    strncpy(result->content, user_input, MAX_INPUT_LENGTH);
    result->content[MAX_INPUT_LENGTH] = '\\0'; // Ensure null termination

    // Generate metadata with safe formatting
    time_t timestamp = time(NULL);
    int written = snprintf(result->metadata, MAX_METADATA_LENGTH + 1,
                          "%ld|%s|%zu", timestamp, category, strlen(user_input));

    if (written >= MAX_METADATA_LENGTH + 1) {
        return -3; // Metadata would be truncated
    }

    return 0;
}`,
      correct: true,
      explanation: `Use bounds-checked functions like strncpy() and snprintf() to prevent buffer overflows`
    },
    // String copy buffer overflow vulnerabilities
    {
      code: `strcpy(result->category, category);`,
      correct: false,
      explanation: 'strcpy() does not check buffer bounds. Category strings longer than 31 characters (32 including null terminator) will overwrite adjacent memory, corrupting other structure fields and potentially causing crashes or security vulnerabilities.'
    },
    {
      code: `sprintf(result->metadata, "%ld|%s|%zu", timestamp, category, strlen(user_input));`,
      correct: false,
      explanation: 'sprintf() does not validate output buffer size. Long timestamps, categories, or combined strings can exceed the 64-character metadata buffer, causing stack buffer overflow.'
    },
    {
      code: `if (strlen(category) <= 32) {
    strcpy(result->category, category);
}`,
      correct: false,
      explanation: 'Incorrect length check with unsafe function. The buffer holds 32 characters including null terminator, so maximum safe string length is 31. Also strcpy() remains unsafe even with length checks.'
    },
    {
      code: `size_t len = strlen(category) < 32 ? strlen(category) : 31;
memcpy(result->category, category, len);`,
      correct: false,
      explanation: 'memcpy() with manual length limiting does not add null terminator. The resulting string may not be properly null-terminated, causing undefined behavior in string operations.'
    },
    {
      code: `strncpy(result->category, category, 32);`,
      correct: false,
      explanation: 'strncpy() without explicit null termination. If the source string is 32 characters or longer, strncpy() will not add a null terminator, creating invalid C strings.'
    },
    {
      code: `char temp[64];
sprintf(temp, "%s", category);
memcpy(result->category, temp, 32);`,
      correct: false,
      explanation: 'sprintf() into temporary buffer is still unsafe and provides no additional protection. The sprintf() call can overflow the temp buffer before memcpy() even executes.'
    },
    {
      code: `for (int i = 0; i < strlen(category) && i < 32; i++) {
    result->category[i] = category[i];
}`,
      correct: false,
      explanation: 'Manual character copying without null termination. While preventing overflow, the loop does not add a null terminator, creating invalid C strings that can cause undefined behavior.'
    },
    {
      code: `char* safe_copy = strndup(category, 31);
strcpy(result->category, safe_copy);
free(safe_copy);`,
      correct: false,
      explanation: 'strndup() followed by strcpy() is redundant and potentially unsafe. Direct string copying with dynamic allocation adds complexity without benefit over direct bounds-checked copying.'
    },
    {
      code: `if (category != NULL) {
    strcpy(result->category, category);
}`,
      correct: false,
      explanation: 'Null pointer check does not prevent buffer overflow. While checking for null pointers is good practice, strcpy() still has no bounds checking and can overflow the destination buffer.'
    }
  ]
}