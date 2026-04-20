import type { Exercise } from '@/data/exercises'

export const cwe787BufferWrite: Exercise = {
  cweId: 'CWE-787',
  name: 'Out-of-bounds Write - User Message Processing',
  language: 'C',

  vulnerableFunction: `void copy_data(char *input) {
  char buffer[10];
  strcpy(buffer, input);
}`,

  vulnerableLine: `strcpy(buffer, input);`,

  options: [
    {
      code: `strncpy(buffer, input, sizeof(buffer) - 1);
buffer[sizeof(buffer) - 1] = '\\0';`,
      correct: true,
      explanation: `strncpy() with size limit prevents overflow`
    },
    {
      code: `memcpy(buffer, input, strlen(input));`,
      correct: false,
      explanation: 'No length check - input can be longer than buffer'
    },
    {
      code: `strcpy(buffer, input + 5);`,
      correct: false,
      explanation: 'Pointer arithmetic doesn\'t fix buffer size issue'
    },
    {
      code: `if (input[0]) strcpy(buffer, input);`,
      correct: false,
      explanation: 'Checking first character doesn\'t validate length'
    },
    {
      code: `strcpy(buffer, input);
buffer[9] = '\\0';`,
      correct: false,
      explanation: 'Null terminator after overflow is too late'
    },
    {
      code: `for (int i = 0; input[i]; i++)
    buffer[i] = input[i];`,
      correct: false,
      explanation: 'Manual loop without bounds check still overflows'
    },
    {
      code: `strcpy(buffer, strlen(input) < 10 ? input : "");`,
      correct: false,
      explanation: 'Ternary check is better but strcpy still used'
    },
    {
      code: `strcpy(&buffer[0], input);`,
      correct: false,
      explanation: 'Pointer syntax doesn\'t change buffer overflow risk'
    },
    {
      code: `if (buffer && input) strcpy(buffer, input);`,
      correct: false,
      explanation: 'Null checks don\'t prevent length-based overflow'
    },
    {
      code: `sprintf(buffer, "%s", input);`,
      correct: false,
      explanation: 'sprintf() has same overflow risk as strcpy()'
    }
  ]
}