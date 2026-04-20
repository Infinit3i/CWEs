import type { Exercise } from '@/data/exercises'

/**
 * CWE-119 exercise: Hostname lookup buffer overflow
 * Based on MITRE demonstrative examples showing buffer overflow vulnerabilities
 */
export const cwe119HostnameLookup: Exercise = {
  cweId: 'CWE-119',
  name: 'Memory Buffer Bounds - Network Hostname Lookup',
  language: 'C++',

  vulnerableFunction: `#include <cstring>
#include <stdexcept>

#define HOSTNAME_SIZE 64

class NetworkUtils {
public:
    static char* host_lookup(const char* user_supplied_addr) {
        char hostname[HOSTNAME_SIZE];

        // Validate address format (basic check)
        if (!is_valid_ip_format(user_supplied_addr)) {
            throw std::invalid_argument("Invalid IP address format");
        }

        // DNS lookup that could return long hostname
        const char* resolved_hostname = perform_dns_lookup(user_supplied_addr);

        // Copy hostname to fixed buffer (VULNERABLE - no bounds checking)
        strcpy(hostname, resolved_hostname);

        // Return copy (unsafe - local buffer)
        char* result = new char[HOSTNAME_SIZE];
        strcpy(result, hostname);
        return result;
    }

private:
    static const char* perform_dns_lookup(const char* addr) {
        // Could return very long hostnames like:
        // "very-long-subdomain.example-with-many-parts.com..."
        return mock_dns_response(addr);
    }
};`,

  vulnerableLine: `strcpy(hostname, resolved_hostname);`,

  options: [
    {
      code: `static char* host_lookup(const char* user_supplied_addr) {
    const int MAX_HOSTNAME_SIZE = 253; // RFC compliant max hostname length

    if (!is_valid_ip_format(user_supplied_addr)) {
        throw std::invalid_argument("Invalid IP address format");
    }

    const char* resolved_hostname = perform_dns_lookup(user_supplied_addr);

    // Check hostname length before copying
    if (strlen(resolved_hostname) >= HOSTNAME_SIZE) {
        throw std::length_error("Hostname too long for buffer");
    }

    char* hostname = new char[HOSTNAME_SIZE];
    strncpy(hostname, resolved_hostname, HOSTNAME_SIZE - 1);
    hostname[HOSTNAME_SIZE - 1] = '\\0'; // Ensure null termination

    return hostname;
}`,
      correct: true,
      explanation: `Use bounds checking and strncpy() with explicit null termination to prevent buffer overflows`
    },
    {
      code: `strcpy(hostname, resolved_hostname);`,
      correct: false,
      explanation: 'strcpy() does not perform bounds checking. A hostname longer than 63 characters (64 including null terminator) will overwrite memory beyond the buffer, corrupting adjacent stack variables and potentially causing crashes or security vulnerabilities.'
    },
    {
      code: `char hostname[HOSTNAME_SIZE];
for (int i = 0; i < strlen(resolved_hostname); i++) {
    hostname[i] = resolved_hostname[i];
}`,
      correct: false,
      explanation: 'Manual character-by-character copy without bounds checking. This loop can write beyond the buffer boundary and also fails to null-terminate the string, causing undefined behavior in subsequent string operations.'
    },
    {
      code: `char* hostname = (char*)malloc(HOSTNAME_SIZE);
memcpy(hostname, resolved_hostname, strlen(resolved_hostname));`,
      correct: false,
      explanation: 'memcpy() with unchecked length parameter allows buffer overflow. If resolved_hostname is longer than HOSTNAME_SIZE, memcpy will write beyond the allocated buffer boundary.'
    },
    {
      code: `char hostname[HOSTNAME_SIZE];
int i = 0;
while (resolved_hostname[i]) {
    hostname[i] = resolved_hostname[i];
    i++;
}`,
      correct: false,
      explanation: 'While loop without destination buffer bounds checking. The loop continues until it hits the null terminator of the source, potentially writing far beyond the destination buffer.'
    },
    {
      code: `char hostname[HOSTNAME_SIZE];
strncat(hostname, resolved_hostname, HOSTNAME_SIZE);`,
      correct: false,
      explanation: 'strncat() on uninitialized buffer is undefined behavior. The destination must be properly initialized, and strncat appends rather than copies, making it inappropriate for this use case.'
    },
    {
      code: `char hostname[HOSTNAME_SIZE];
if (strlen(resolved_hostname) < 100) {
    strcpy(hostname, resolved_hostname);
}`,
      correct: false,
      explanation: 'Insufficient bounds checking with unsafe function. Checking for length < 100 when buffer is only 64 bytes still allows overflow for hostnames 64-99 characters long.'
    },
    {
      code: `char hostname[HOSTNAME_SIZE];
strncpy(hostname, resolved_hostname, HOSTNAME_SIZE);`,
      correct: false,
      explanation: 'strncpy() without explicit null termination. If the source string equals or exceeds HOSTNAME_SIZE, strncpy will not null-terminate the destination, creating an invalid C string.'
    },
    {
      code: `sprintf(hostname, "%s", resolved_hostname);`,
      correct: false,
      explanation: 'sprintf() does not perform bounds checking on the destination buffer. Long hostnames will overflow the buffer, causing stack corruption and potential security vulnerabilities.'
    },
    {
      code: `char hostname[HOSTNAME_SIZE];
memset(hostname, 0, HOSTNAME_SIZE);
if (strlen(resolved_hostname) <= HOSTNAME_SIZE) {
    strcpy(hostname, resolved_hostname);
}`,
      correct: false,
      explanation: 'Off-by-one error in bounds checking with unsafe function. A string of exactly HOSTNAME_SIZE characters plus null terminator will overflow. Also strcpy() remains inherently unsafe.'
    }
  ]
}