import type { CWEData } from '@/services/cweAPI'

export interface ExerciseOption {
  code: string
  correct: boolean
  explanation: string
}

export interface Exercise {
  cweId: string
  name: string
  vulnerableFunction: string
  vulnerableLine: string
  options: ExerciseOption[]
  cweData?: CWEData  // API-fetched CWE data
}

// Import all exercises from individual files
export { exercisesList as exercises } from './exercises/index'