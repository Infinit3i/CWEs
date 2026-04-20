#!/usr/bin/env node

/**
 * Script to generate new CWE exercise files from template
 *
 * Usage: node generate-exercise.js CWE-XXX "Exercise Name"
 */

const fs = require('fs')
const path = require('path')

function generateExercise(cweId, exerciseName) {
  if (!cweId || !exerciseName) {
    console.log('Usage: node generate-exercise.js CWE-XXX "Exercise Name"')
    console.log('Example: node generate-exercise.js CWE-79 "Cross-Site Scripting"')
    return
  }

  const fileName = `${cweId.toLowerCase()}-${exerciseName.toLowerCase().replace(/[^a-z0-9]+/g, '-')}.ts`
  const exercisesDir = path.join(__dirname, '..', 'data', 'exercises')
  const filePath = path.join(exercisesDir, fileName)

  // Read template
  const templatePath = path.join(__dirname, 'cwe-exercise-template.ts')
  let template = fs.readFileSync(templatePath, 'utf8')

  // Replace placeholders
  const exportName = `${cweId.toLowerCase().replace('-', '')}${exerciseName.replace(/[^a-zA-Z0-9]/g, '')}`

  template = template.replace('[CWE-XXX]', cweId)
  template = template.replace('[CWE Type] - [Scenario Description]', exerciseName)
  template = template.replace('export const cweTemplate: Exercise =', `export const ${exportName}: Exercise =`)

  // Write new exercise file
  fs.writeFileSync(filePath, template)

  console.log(`✅ Generated new exercise file: ${fileName}`)
  console.log(`📝 Edit the file at: ${filePath}`)
  console.log(`🔗 Don't forget to add it to src/data/exercises/index.ts:`)
  console.log(`   import { ${exportName} } from './${fileName.replace('.ts', '')}'`)
  console.log(`   // Add ${exportName} to the exercisesList array`)
  console.log(`ℹ️  Note: CWE data (CVEs, severity, mitigation) will be automatically`)
  console.log(`   fetched from the MITRE API when the exercise loads.`)
}

// Get command line arguments
const [,, cweId, exerciseName] = process.argv
generateExercise(cweId, exerciseName)