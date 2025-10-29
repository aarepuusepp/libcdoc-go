# Vue.js + TypeScript Rules (test-frontend)

## Context
Use when working on the `test-frontend/` project specifically.

## Technology Stack
- Vue.js 3 with Composition API
- TypeScript with strict mode
- PrimeVue UI components
- Tailwind CSS for styling
- Vite for build tooling
- Vue Router for navigation

## Key Patterns

### Component Structure
```typescript
<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import type { ComponentType } from '@/types'

// Use Composition API consistently
const state = ref<ComponentType>()
const computedValue = computed(() => state.value?.property)

onMounted(async () => {
  // Initialization logic
})
</script>

<template>
  <div class="container mx-auto p-4">
    <!-- Use PrimeVue components with proper TypeScript types -->
    <Button @click="handleClick" :disabled="loading">
      {{ buttonText }}
    </Button>
  </div>
</template>
```

### Authentication Integration
- Use Pinia stores for state management
- Implement proper JWT handling with httpOnly cookies
- Handle UAA OAuth flows with proper error handling
- Type all API responses and authentication states

### File Organization
- Components: `src/components/`
- Views: `src/views/`
- Stores: `src/stores/`
- Types: `src/types/`
- Router: `src/router/`

## Critical Rules
- Always use `<script setup lang="ts">` syntax
- Type all props, emits, and reactive data
- Use PrimeVue components consistently
- Apply Tailwind classes for styling
- Handle loading and error states properly
- Use Vue Router with TypeScript route definitions 