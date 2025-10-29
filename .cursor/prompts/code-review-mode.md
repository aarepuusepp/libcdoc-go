# Code Review Mode

## Purpose

Systematically analyze code changes to ensure full compliance with all defined rules and standards across the codebase. This mode performs comprehensive analysis of modified files against all established code standards, architecture patterns, implementation requirements, and best practices.

## Process Flow

1. **Identify Changed Files**:

   - If specific files were requested to review, use those
   - Otherwise, detect changed files using git:

     ```bash
     # Better command for detecting changes (combines staged and unstaged changes)
     git diff --name-only HEAD
     # Alternative that includes untracked files
     git ls-files --others --modified --exclude-standard
     ```

2. **For Each File**:

   - CRITICAL: Analyze each file SEPARATELY against EACH relevant cursor rule
   - Maintain a checklist to ensure no rules are skipped
   - Note both compliance and non-compliance
   - Prioritize issues by severity

3. **Generate a Structured Compliance Report**:

   - File-by-file breakdown
   - Rule-by-rule evaluation
   - Clear distinction between:
     - Critical issues (security, performance)
     - Standard violations
     - Style inconsistencies
     - Best practice suggestions

4. **Propose Specific Fixes for Non-compliant Code**:
   - Provide concrete code examples for fixing issues
   - Explain the reasoning behind each fix
   - Consider the impact of changes

## Compliance Checks

Code Review Mode should dynamically check each file against ALL available cursor rules:

1. **Dynamically Identify All Rules**:

   - Scan the `.cursor/rules/` directory for all `.mdc` rules files
   - Use the `fetch_rules` function to get the full list of available rules
   - Do not limit analysis to a predefined set of rules

2. **Categorize by Rule Prefix**:

   - Rules are typically prefixed with numbers (e.g., 000-, 010-, etc.)
   - Create a dynamic checklist of all available rules
   - Mark each rule as reviewed during the analysis process

3. **Ensure Complete Coverage**:
   - Verify that EVERY rule has been considered for EACH file
   - Rules may not all be applicable to every file, but each must be considered

This approach ensures that no rules are overlooked as the rule set evolves over time, and that new rules are automatically incorporated into the review process without requiring updates to this guide.

**Example Rule Categories** (for reference only, actual rules should be dynamically determined):

- Code Standards
- Architecture
- Implementation
- Framework-specific
- Performance
- Security
- Testing
- Component Guidelines
- Process and Workflow

## Review Structure

For each file, use this template:

```format
### File: [filename]

#### Compliance Summary
- Overall Assessment: [Compliant/Minor Issues/Major Issues]
- Critical Issues: [Count]
- Standard Violations: [Count]
- Enhancement Opportunities: [Count]

#### Rule Analysis

##### [Rule Name]
- Compliance: [Full/Partial/Non-compliant]
- Findings:
  - [Specific issue or compliance point]
  - [Line numbers and context]
- Recommendations:
  - [Specific actionable changes]

[repeat for each applicable rule]

#### Functional Analysis
- Logic Issues: [Description]
- Performance Concerns: [Description]
- Security Considerations: [Description]
```

## Report Format

For each file, the report will:

1. Identify the file and its purpose
2. List all non-compliance issues grouped by rule category
3. Indicate severity level for each issue (Critical, High, Medium, Low)
4. Provide the specific line numbers where issues occur
5. Explain the violation with reference to the specific rule
6. Suggest a compliant alternative

## Sample Output Structure

```format
## File: components/ExampleComponent.vue

### Non-compliance issues:

#### Code Standards (000-code-standards)
- [Critical] Line 12-15: Missing JSDoc documentation for component props
- [Medium] Line 27: Inconsistent naming convention, using snake_case instead of camelCase

#### Implementation (020-implementation)
- [High] Line 45-60: Direct DOM manipulation instead of using refs
- [Medium] Line 72: Direct localStorage usage instead of using storage utilities

#### Security (050-security)
- [Critical] Line 104: Unsanitized input used in v-html directive

### Would you like me to fix these issues? I can address them in the following order:
1. Critical security issues
2. Critical and high-priority code standard violations
3. Implementation issues
4. Lower priority issues
```

## Commands and Tools

Useful commands during code review:

```bash
# View changes in a specific file
git diff [filename]

# See commit history for file
git log -p [filename]

# Check who last modified each line
git blame [filename]

# Find related files
grep -r "SearchTerm" --include="*.extension" .
```

## Remediation Process

When authorized to fix issues:

1. Focus on critical issues first, especially security concerns
2. Make systematic changes with clear documentation
3. Address one category of issues at a time
4. Provide before/after comparisons for complex changes
5. Explain the reasoning behind each fix
6. Update documentation as needed

## Critical Success Factors

- Never skip rules - use a checklist to track progress
- Always separate the review by file AND by rule
- Prioritize issues by impact on security, functionality, and maintainability
- Provide specific line references for all issues
- Include both what to fix and why to fix it

## Usage

To enter Code Review Mode:

```format
Enter Code Review Mode: review all changed files
```

Or for specific files:

```format
Enter Code Review Mode: review components/Header.vue and utils/validation.ts
```

After initial review, you can request partial or complete fixes:

```format
Fix all critical and high issues
```

Or:

```format
Fix all issues in components/Header.vue
```

## Outputs

1. **Analysis Report**: Detailed breakdown of compliance issues
2. **Fix Proposal**: Proposed changes to address identified issues
3. **Implementation**: Actual code changes to fix non-compliant code
4. **Documentation Updates**: Any required updates to associated documentation
