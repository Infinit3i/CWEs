<template>
  <div class="cwe-viewer">
    <div class="header">
      <h1>{{ currentExercise.cweId }}: {{ currentExercise.name }}</h1>
      <div class="nav">
        <span class="counter">Exercise {{ exerciseCount }}</span>
        <button v-if="isCorrectAnswer" @click="nextRandomExercise" class="next-btn">
          Next →
        </button>
      </div>
    </div>

    <div class="exercise">
      <div class="exercise-content">
        <div class="code-section">
          <div class="code-block">
            <div class="language-indicator">{{ currentExercise.language }}</div>
            <div
              v-if="showTryAgainOverlay"
              class="try-again-overlay"
              :class="{ 'fading-out': isFadingOut }"
            >
              TRY AGAIN
            </div>
            <pre><code>{{ renderFunctionStart() }}<span
        class="vulnerable-line"
        :class="{ 'drag-over': isDragOver, 'replaced': droppedOption !== null }"
        @dragover.prevent="handleDragOver"
        @dragleave="handleDragLeave"
        @drop="handleDrop"
      >{{ droppedOption !== null ? currentExercise.options[droppedOption].code : currentExercise.vulnerableLine }}</span>{{ renderFunctionEnd() }}</code></pre>
          </div>
        </div>

        <div class="options-section">
          <div v-if="!isCorrectAnswer" class="options">
            <div
              v-for="option in shuffledOptions"
              :key="option.originalIndex"
              class="option"
              :class="{ 'dragging': draggingIndex === option.originalIndex }"
              draggable="true"
              @dragstart="handleDragStart(option.originalIndex, $event)"
              @dragend="handleDragEnd"
            >
              {{ option.code }}
            </div>
          </div>

          <div v-if="droppedOption !== null && !showTryAgainOverlay" class="result">
        <div v-if="!currentExercise.options[droppedOption].correct" class="wrong">
          {{ currentExercise.options[droppedOption].explanation }}
          <button @click="reset" class="try-again">Try Again</button>
        </div>
        <div v-else class="cve-list">
          <div class="explanation">
            {{ currentExercise.options[droppedOption].explanation }}
          </div>

          <div v-if="loadingCWE" class="loading">
            Loading CWE data from MITRE API...
          </div>

          <div v-else-if="cweError" class="error">
            Error loading CWE data: {{ cweError }}
          </div>

          <div v-else-if="cweData" class="cwe-info">
            <h2>{{ cweData.name }}</h2>

            <div class="cwe-section">
              <h3>Severity & Likelihood</h3>
              <div class="severity-info">
                <span class="severity">{{ cweData.severity }}</span>
                <span class="likelihood">{{ cweData.likelihood }} likelihood</span>
              </div>
            </div>

            <div class="cwe-section">
              <h3>Attack Vectors</h3>
              <ul class="attack-vectors">
                <li v-for="vector in cweData.attackVectors.slice(0, 4)" :key="vector">
                  {{ vector }}
                </li>
              </ul>
            </div>

            <div class="cwe-section">
              <h3>Related CVEs</h3>
              <div class="cves">
                <div v-for="cve in cweData.relatedCVEs.slice(0, 6)" :key="cve" class="cve">
                  <a :href="`https://nvd.nist.gov/vuln/detail/${cve}`" target="_blank" class="cve-number">
                    {{ cve }}
                  </a>
                </div>
              </div>
            </div>

            <div class="cwe-section">
              <h3>Mitigation</h3>
              <ul class="mitigation">
                <li v-for="method in cweData.mitigation.slice(0, 3)" :key="method">
                  {{ method }}
                </li>
              </ul>
            </div>
          </div>
        </div>
      </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue'
import { exercises } from '@/data/exercises'
import { CWEAPIService, type CWEData } from '@/services/cweAPI'

const droppedOption = ref<number | null>(null)
const draggingIndex = ref<number | null>(null)
const isDragOver = ref(false)
const shuffleKey = ref(0)
const exerciseCount = ref(1)
const currentExerciseIndex = ref(0)
const showTryAgainOverlay = ref(false)
const isFadingOut = ref(false)

// CWE API data
const cweData = ref<CWEData | null>(null)
const loadingCWE = ref(false)
const cweError = ref<string | null>(null)

// Initialize with random exercise
function getRandomExercise(): number {
  return Math.floor(Math.random() * exercises.length)
}

const currentExercise = computed(() => exercises[currentExerciseIndex.value])
const isCorrectAnswer = computed(() =>
  droppedOption.value !== null && currentExercise.value.options[droppedOption.value].correct
)

const shuffledOptions = computed(() => {
  shuffleKey.value
  const allOptions = currentExercise.value.options.map((option, index) => ({
    ...option,
    originalIndex: index
  }))

  // Find correct and wrong options
  const correctOption = allOptions.find(option => option.correct)
  const wrongOptions = allOptions.filter(option => !option.correct)

  // Randomly select 5 wrong options
  const shuffledWrong = [...wrongOptions]
  for (let i = shuffledWrong.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [shuffledWrong[i], shuffledWrong[j]] = [shuffledWrong[j], shuffledWrong[i]]
  }
  const selectedWrong = shuffledWrong.slice(0, 5)

  // Combine correct + 5 wrong and shuffle the final set
  const finalOptions = [correctOption, ...selectedWrong]
  for (let i = finalOptions.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [finalOptions[i], finalOptions[j]] = [finalOptions[j], finalOptions[i]]
  }

  return finalOptions
})

// Fetch CWE data from API
async function fetchCWEData(cweId: string) {
  if (cweData.value?.id === cweId) return // Already loaded

  loadingCWE.value = true
  cweError.value = null

  try {
    const id = cweId.replace('CWE-', '') // Extract number from "CWE-89"
    cweData.value = await CWEAPIService.fetchCWE(id)
  } catch (error) {
    cweError.value = error instanceof Error ? error.message : 'Failed to fetch CWE data'
    console.error('Error fetching CWE data:', error)
  } finally {
    loadingCWE.value = false
  }
}

// Fetch CWE data when component mounts
onMounted(() => {
  // Start with random exercise
  currentExerciseIndex.value = getRandomExercise()
  if (currentExercise.value) {
    fetchCWEData(currentExercise.value.cweId)
  }
})

// Watch for exercise changes
watch(currentExerciseIndex, () => {
  if (currentExercise.value) {
    fetchCWEData(currentExercise.value.cweId)
  }
})

function handleDragStart(index: number, event: DragEvent) {
  draggingIndex.value = index
  event.dataTransfer!.setData('text/plain', index.toString())
}

function handleDragEnd() {
  draggingIndex.value = null
}

function handleDragOver() {
  isDragOver.value = true
}

function handleDragLeave() {
  isDragOver.value = false
}

function handleDrop(event: DragEvent) {
  event.preventDefault()
  isDragOver.value = false
  if (droppedOption.value !== null) return
  droppedOption.value = parseInt(event.dataTransfer!.getData('text/plain'))
}

function reset() {
  droppedOption.value = null
  shuffleKey.value++
}

function nextRandomExercise() {
  // Get a random exercise (may be the same one, that's ok)
  currentExerciseIndex.value = getRandomExercise()
  droppedOption.value = null
  shuffleKey.value++
  exerciseCount.value++
}

function renderFunctionStart() {
  const exercise = currentExercise.value
  const vulnerableLineIndex = exercise.vulnerableFunction.indexOf(exercise.vulnerableLine)
  return exercise.vulnerableFunction.substring(0, vulnerableLineIndex)
}

function renderFunctionEnd() {
  const exercise = currentExercise.value
  const vulnerableLineIndex = exercise.vulnerableFunction.indexOf(exercise.vulnerableLine)
  const vulnerableLineEndIndex = vulnerableLineIndex + exercise.vulnerableLine.length
  return exercise.vulnerableFunction.substring(vulnerableLineEndIndex)
}
</script>

<style scoped>
.cwe-viewer {
  width: 100%;
  max-width: 1600px;
  margin: 0 auto;
  padding: 1rem;
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
  box-sizing: border-box;
  overflow-x: hidden;
}

.header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 2rem;
  width: 100%;
}

.header h1 {
  margin: 0;
  font-size: 1.5rem;
  font-weight: 600;
  color: #f8fafc;
}

.nav {
  display: flex;
  align-items: center;
  gap: 1rem;
}

.next-btn {
  padding: 0.5rem 1rem;
  border-radius: 8px;
  border: 1px solid #10b981;
  background: #059669;
  color: white;
  cursor: pointer;
  transition: all 0.2s;
  font-size: 0.9rem;
  font-weight: 500;
}

.next-btn:hover {
  background: #047857;
  border-color: #059669;
  transform: translateY(-1px);
}

.counter {
  font-size: 0.9rem;
  color: #9ca3af;
  min-width: 60px;
  text-align: center;
}

.exercise {
  background: #1f2937;
  border-radius: 12px;
  padding: 1.5rem;
  border: 1px solid #374151;
  width: 90%;
  max-width: 1400px;
  margin: 0 auto;
  box-sizing: border-box;
  overflow: hidden;
}

/* Desktop layout: side-by-side */
.exercise-content {
  display: flex;
  gap: 2%;
  align-items: flex-start;
  width: 100%;
  box-sizing: border-box;
  overflow: hidden;
}

@media (max-width: 768px) {
  .exercise-content {
    flex-direction: column;
    gap: 1.5rem;
  }

  .exercise {
    width: 95%;
  }
}

.code-section {
  flex: 0 0 63%;
  min-width: 0;
  overflow: hidden;
  box-sizing: border-box;
}

.options-section {
  flex: 0 0 35%;
  min-width: 0;
  overflow: hidden;
  box-sizing: border-box;
}

.code-block {
  background: #111827;
  border-radius: 8px;
  padding: 1.5rem;
  border: 1px solid #374151;
  position: relative;
  width: 100%;
  max-width: 100%;
  box-sizing: border-box;
  overflow: hidden;
}

.language-indicator {
  position: absolute;
  top: 0.5rem;
  left: 1rem;
  background: #374151;
  color: #9ca3af;
  padding: 0.25rem 0.75rem;
  border-radius: 4px;
  font-size: 0.75rem;
  font-weight: 500;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  font-family: 'SF Mono', Monaco, 'Cascadia Code', monospace;
  z-index: 1;
}

.code-block pre {
  margin: 1.5rem 0 0 0;
  color: #f8fafc;
  font-family: 'SF Mono', Monaco, 'Cascadia Code', monospace;
  font-size: 14px;
  line-height: 1.6;
  text-align: left;
  white-space: pre-wrap;
  word-break: break-word;
  overflow-wrap: break-word;
  width: 100%;
  max-width: 100%;
  box-sizing: border-box;
  padding: 0;
  overflow: hidden;
}

@media (max-width: 768px) {
  .code-block pre {
    font-size: 14px;
    line-height: 1.6;
  }
}

.vulnerable-line {
  background: #fbbf24;
  color: #000;
  padding: 4px 8px;
  border-radius: 4px;
  cursor: pointer;
  transition: all 0.2s;
  display: inline;
  word-break: break-word;
  overflow-wrap: break-word;
}

.vulnerable-line.drag-over {
  background: #60a5fa;
  transform: scale(1.02);
  box-shadow: 0 0 0 2px #3b82f6;
}

.vulnerable-line.replaced {
  background: #10b981;
  color: #fff;
  font-weight: 500;
}

.options {
  display: grid;
  gap: 0.75rem;
  width: 100%;
  box-sizing: border-box;
}

.option {
  background: #374151;
  border: 1px solid #4b5563;
  border-radius: 8px;
  padding: 0.75rem;
  cursor: grab;
  transition: all 0.2s;
  font-family: 'SF Mono', Monaco, 'Cascadia Code', monospace;
  font-size: 12px;
  color: #f8fafc;
  word-break: break-word;
  overflow-wrap: break-word;
  white-space: pre-wrap;
  width: 100%;
  box-sizing: border-box;
}

.option:hover {
  background: #4b5563;
  border-color: #6b7280;
  transform: translateY(-1px);
}

.option.dragging {
  opacity: 0.5;
  cursor: grabbing;
}

.result {
  margin-top: 2rem;
  padding-top: 2rem;
  border-top: 1px solid #374151;
  width: 100%;
  max-width: 100%;
  box-sizing: border-box;
  overflow: hidden;
  word-break: break-word;
}

.wrong {
  background: #fef2f2;
  border: 1px solid #fecaca;
  border-radius: 8px;
  padding: 1rem;
  color: #dc2626;
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.try-again {
  background: #dc2626;
  color: white;
  border: none;
  padding: 0.5rem 1rem;
  border-radius: 6px;
  cursor: pointer;
  font-weight: 500;
  font-size: 0.9rem;
}

.try-again:hover {
  background: #b91c1c;
}

.explanation {
  background: #065f46;
  border: 1px solid #059669;
  border-radius: 8px;
  padding: 1rem;
  margin-bottom: 2rem;
  color: #d1fae5;
  line-height: 1.6;
  font-size: 0.95rem;
}

.cve-list h2 {
  margin: 0 0 1.5rem 0;
  font-size: 1.25rem;
  font-weight: 600;
  color: #f8fafc;
}

.cves {
  display: grid;
  gap: 1rem;
}

.cve {
  display: flex;
  flex-direction: row;
  align-items: center;
  gap: 1rem;
  padding: 0.125rem 0;
}

@media (max-width: 768px) {
  .cve {
    flex-direction: column;
    gap: 0.75rem;
  }
}

.cve-number {
  color: #60a5fa;
  text-decoration: none;
  font-weight: 600;
  font-size: 0.95rem;
  font-family: 'SF Mono', Monaco, 'Cascadia Code', monospace;
  min-width: 160px;
  white-space: nowrap;
  flex-shrink: 0;
}

.cve-number:hover {
  color: #93c5fd;
  text-decoration: underline;
}

.vulnerability {
  color: #fbbf24;
  font-size: 0.9rem;
  line-height: 1.4;
  padding: 0.75rem;
  background: #374151;
  border-radius: 6px;
  border-left: 3px solid #f59e0b;
  flex: 1;
}

/* New CWE API styles */
.loading {
  text-align: center;
  color: #9ca3af;
  font-style: italic;
  padding: 2rem;
}

.error {
  background: #fef2f2;
  border: 1px solid #fecaca;
  border-radius: 8px;
  padding: 1rem;
  color: #dc2626;
  text-align: center;
}

.cwe-info h2 {
  margin: 0 0 1.5rem 0;
  font-size: 1.25rem;
  font-weight: 600;
  color: #f8fafc;
}

.cwe-section {
  margin-bottom: 1.5rem;
}

.cwe-section h3 {
  margin: 0 0 0.75rem 0;
  font-size: 1rem;
  font-weight: 600;
  color: #d1d5db;
}

.severity-info {
  display: flex;
  gap: 1rem;
  align-items: center;
}

.severity {
  background: #dc2626;
  color: white;
  padding: 0.25rem 0.75rem;
  border-radius: 4px;
  font-size: 0.875rem;
  font-weight: 500;
}

.likelihood {
  background: #374151;
  color: #d1d5db;
  padding: 0.25rem 0.75rem;
  border-radius: 4px;
  font-size: 0.875rem;
}

.attack-vectors, .mitigation {
  list-style: none;
  padding: 0;
  margin: 0;
}

.attack-vectors li, .mitigation li {
  background: #374151;
  border-left: 3px solid #60a5fa;
  padding: 0.75rem;
  margin-bottom: 0.5rem;
  border-radius: 4px;
  color: #f8fafc;
  font-size: 0.9rem;
  line-height: 1.4;
}

.mitigation li {
  border-left-color: #10b981;
}

.cves {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: 0.75rem;
}

.cves .cve {
  background: #374151;
  border-radius: 6px;
  padding: 0.75rem;
  text-align: center;
}

.cves .cve-number {
  min-width: auto;
  font-size: 0.875rem;
  display: block;
}
</style>