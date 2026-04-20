import type { Exercise } from '@/data/exercises'

export const cwe787NegativeIndex: Exercise = {
  cweId: 'CWE-787',
  name: 'Out-of-bounds Write - String Replacement Buffer',
  language: 'C',

  vulnerableFunction: `#include <string.h>
#include <stdlib.h>

int replace_text_in_buffer(char* dest_buffer, size_t buffer_size,
                          const char* search_text, const char* replacement) {
    char* found_ptr = strstr(dest_buffer, search_text);
    char* write_ptr;

    if (found_ptr == NULL) {
        // Not found, calculate offset from null pointer
        write_ptr = found_ptr - buffer_size;
    } else {
        write_ptr = found_ptr;
    }

    // Write replacement text (VULNERABLE)
    for (size_t i = 0; i < strlen(replacement); i++) {
        write_ptr[i] = replacement[i];
    }

    return 0;
}`,

  vulnerableLine: `write_ptr[i] = replacement[i];`,

  options: [
    {
      code: `int replace_text_in_buffer(char* dest_buffer, size_t buffer_size,
                          const char* search_text, const char* replacement) {
    char* found_ptr = strstr(dest_buffer, search_text);

    if (found_ptr == NULL) {
        return -1; // Not found, return error
    }

    // Check if replacement fits in buffer
    size_t search_len = strlen(search_text);
    size_t replace_len = strlen(replacement);
    size_t offset = found_ptr - dest_buffer;

    if (offset + replace_len >= buffer_size) {
        return -2; // Replacement too long
    }

    // Safe replacement
    memcpy(found_ptr, replacement, replace_len);

    return 0;
}`,
      correct: true,
      explanation: `Validate pointer before use and check buffer bounds to prevent negative index writes`
    },
    {
      code: `write_ptr = found_ptr - buffer_size;`,
      correct: false,
      explanation: 'When strstr() returns NULL (not found), this calculation produces a large negative pointer. Writing through negative pointers corrupts memory before the buffer start, potentially overwriting critical program data or causing segmentation faults.'
    },
    {
      code: `char* safe_ptr = (found_ptr != NULL) ? found_ptr : dest_buffer;
for (size_t i = 0; i < strlen(replacement); i++) {
    safe_ptr[i] = replacement[i];
}`,
      correct: false,
      explanation: 'Writing to buffer start when text not found overwrites existing data with replacement text, corrupting buffer contents. The original data is lost without proper error handling.'
    },
    {
      code: `if (found_ptr != NULL) {
    write_ptr = found_ptr;
} else {
    write_ptr = dest_buffer + buffer_size;
}`,
      correct: false,
      explanation: 'Setting pointer to buffer_size when not found creates out-of-bounds write past the end of allocated memory, causing heap corruption or segmentation faults.'
    },
    {
      code: `ptrdiff_t offset = found_ptr ? (found_ptr - dest_buffer) : -1;
if (offset >= 0) {
    for (size_t i = 0; i < strlen(replacement); i++) {
        dest_buffer[offset + i] = replacement[i];
    }
}`,
      correct: false,
      explanation: 'Missing upper bounds check allows writing past buffer end. While preventing negative writes, long replacements can still overflow the buffer boundary.'
    },
    {
      code: `if (found_ptr) {
    memcpy(found_ptr, replacement, strlen(replacement));
}`,
      correct: false,
      explanation: 'memcpy() without bounds checking can write past buffer end. If the replacement string is longer than remaining buffer space, this causes buffer overflow.'
    },
    {
      code: `size_t write_index = (found_ptr == NULL) ? 0 : (found_ptr - dest_buffer);
if (write_index < buffer_size) {
    for (size_t i = 0; i < strlen(replacement); i++) {
        dest_buffer[write_index + i] = replacement[i];
    }
}`,
      correct: false,
      explanation: 'Per-character bounds checking only validates start position. The loop can still write past buffer end if write_index + replacement length exceeds buffer_size.'
    },
    {
      code: `char* write_ptr = found_ptr ? found_ptr : (dest_buffer - 1);
for (size_t i = 0; i < strlen(replacement); i++) {
    if (write_ptr + i >= dest_buffer) {
        write_ptr[i] = replacement[i];
    }
}`,
      correct: false,
      explanation: 'Attempting to create negative pointer (dest_buffer - 1) is undefined behavior. Pointer arithmetic outside allocated memory bounds has unpredictable results in C.'
    },
    {
      code: `if (found_ptr == NULL) found_ptr = dest_buffer;
strcpy(found_ptr, replacement);`,
      correct: false,
      explanation: 'strcpy() does not perform bounds checking and overwrites buffer start when text not found. Both issues corrupt buffer contents without validation.'
    },
    {
      code: `uintptr_t addr = (uintptr_t)found_ptr;
if (addr > 0) {
    memcpy(found_ptr, replacement, strlen(replacement));
}`,
      correct: false,
      explanation: 'Checking pointer address against 0 is insufficient for null pointer detection and provides no protection against buffer overflow from long replacement strings.'
    }
  ]
}