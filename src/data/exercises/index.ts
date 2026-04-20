import { cwe89Select } from './cwe-89-select'
import { cwe89Login } from './cwe-89-login'
import { cwe89Update } from './cwe-89-update'
import { cwe89Delete } from './cwe-89-delete'
import { cwe89Insert } from './cwe-89-insert'
import { cwe89Search } from './cwe-89-search'
import { cwe79Example } from './cwe-79-example'
import type { Exercise } from '@/data/exercises'

/**
 * All CWE exercises imported from individual files
 *
 * To add a new exercise:
 * 1. Create a new file following the template in /src/templates/cwe-exercise-template.ts
 * 2. Import it above
 * 3. Add it to the exercisesList array below
 */

export const exercisesList: Exercise[] = [
  cwe89Select,
  cwe89Login,
  cwe89Update,
  cwe89Delete,
  cwe89Insert,
  cwe89Search,
  cwe79Example,
  // Add new exercises here
]

export { cwe89Select, cwe89Login, cwe89Update, cwe89Delete, cwe89Insert, cwe89Search, cwe79Example }