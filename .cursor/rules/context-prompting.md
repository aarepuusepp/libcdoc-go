# Context-Aware Prompting Guide

## Purpose
Guidelines for making smaller, more effective requests to get better results from AI assistance.

## Request Structure Templates

### For Single Project Work
```
"Working on [PROJECT_NAME]: [specific task description]"

Examples:
- "Working on test-frontend: Add logout button to navigation component"
- "Working on uaa-auth: Fix token validation error handling"
- "Working on openapi-generator: Update struct tags for new API spec"
```

### For Cross-Project Integration
```
"Cross-project task affecting [PROJECT1] and [PROJECT2]: [specific task]"

Examples:
- "Cross-project task affecting uaa-auth and test-frontend: Implement token refresh flow"
- "Cross-project task affecting openapi-generator and test-backend: Add new user management endpoints"
```

### For Configuration Changes
```
"KrakenD config update: [specific configuration change]"

Examples:
- "KrakenD config update: Add CORS for new frontend domain"
- "KrakenD config update: Configure rate limiting for API endpoints"
```

## Context Clues to Include

### File Context
- Mention specific files you're working with
- Include relevant directory paths
- Reference related configuration files

### Technology Context
- Specify the tech stack (Go, Vue.js, TypeScript)
- Mention relevant frameworks (PrimeVue, KrakenD plugin system)
- Include version information when relevant

### Functional Context
- Describe the specific feature or behavior
- Mention related components or services
- Include error messages or symptoms

## Examples of Well-Structured Requests

### ✅ Good: Specific and Focused
```
"Working on test-frontend: The LoginView.vue component needs to handle UAA authentication errors properly. Currently getting 401 responses but not showing user-friendly error messages."
```

### ✅ Good: Cross-Project with Clear Scope
```
"Cross-project task affecting uaa-auth and test-frontend: Need to implement logout functionality that revokes tokens in Redis and clears frontend state."
```

### ❌ Avoid: Too Broad
```
"Fix authentication issues"
```

### ❌ Avoid: Missing Context
```
"Add a button to the page"
```

## Quick Reference

### Project Prefixes
- `test-frontend:` - Vue.js/TypeScript frontend work
- `uaa-auth:` - KrakenD UAA plugin development
- `test-backend:` - Go API server tasks
- `openapi-generator:` - OpenAPI to KrakenD config generation
- `KrakenD config:` - Configuration file modifications

### Common Task Types
- **Feature addition**: "Add [feature] to [component/service]"
- **Bug fix**: "Fix [specific issue] in [specific location]"
- **Configuration**: "Update [config type] for [specific purpose]"
- **Integration**: "Connect [service A] with [service B] for [purpose]"
- **Refactoring**: "Improve [specific code/pattern] in [location]"

## Benefits of This Approach
- Faster, more accurate responses
- Less back-and-forth clarification
- Better context retention across conversations
- More focused code suggestions
- Reduced chance of incorrect assumptions 