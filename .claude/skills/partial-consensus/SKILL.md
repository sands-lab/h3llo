---
name: partial-consensus
description: Synthesize consensus plan(s) from multi-agent debate - provides multiple options when no agreement
allowed-tools:
  - Bash(.claude/skills/partial-consensus/scripts/partial-consensus.sh:*)
  - Bash(cat:*)
  - Bash(test:*)
  - Bash(wc:*)
  - Bash(grep:*)
---

# Partial Consensus Skill

This skill synthesizes implementation plans from a multi-agent debate with dual proposers, **preserving agent perspectives** and **exposing disagreements as developer decisions** rather than auto-resolving them.

## Key Features

- **Agent Perspectives Preserved**: Overall summary table + per-disagreement tables
- **No Silent Resolution**: Disagreements are never auto-resolved
- **Developer Decision Points**: Each disagreement presents A/B/C options
- **Collapsible Code Drafts**: `<details>` tags for implementation details

## When Disagreement Sections Are Generated

The skill includes disagreement sections when:
1. Bold and Paranoia propose different approaches to the same sub-problem
2. Critique identifies valid arguments for both positions
3. The choice materially affects implementation

## Inputs

This skill requires exactly 5 agent report file paths:
- **Report 1**: Bold proposer report (`.tmp/issue-[refine-]{N}-bold.md`)
- **Report 2**: Paranoia proposer report (`.tmp/issue-[refine-]{N}-paranoia.md`)
- **Report 3**: Critique report (`.tmp/issue-[refine-]{N}-critique.md`)
- **Report 4**: Proposal reducer report (`.tmp/issue-[refine-]{N}-proposal-reducer.md`)
- **Report 5**: Code reducer report (`.tmp/issue-[refine-]{N}-code-reducer.md`)

## Outputs

**Files created:**
- `.tmp/issue-[refine-]{N}-debate.md` - Combined 5-agent debate report
- `.tmp/issue-[refine-]{N}-consensus.md` - Final plan(s)

**Output format (unified):**
```markdown
# Implementation Plan: {Feature Name}

## Agent Perspectives Summary

| Agent | Core Position | Key Insight |
|-------|---------------|-------------|
| Bold | ... | ... |
| Paranoia | ... | ... |
| Critique | ... | ... |
| Proposal Reducer | ... | ... |
| Code Reducer | ... | ... |

## Goal / Codebase Analysis / Implementation Steps
[Standard sections for agreed elements]

## Disagreement 1: {Topic}

### Agent Perspectives
[Per-disagreement table showing each agent's position]

### Resolution Options

#### Option 1A/1B/1C
- Summary, Source, File Changes, Implementation Steps
- Code Draft in `<details>` block
- Risks/Mitigations

**AI Recommendation**: Option [X] because [rationale]
> Note: Developer must make final decision.

## Overall Recommendation
**Suggested combination**: [e.g., "1B + 2A"] because [rationale]
```

## Implementation Workflow

### Step 1: Invoke Partial Consensus Script

```bash
.claude/skills/partial-consensus/scripts/partial-consensus.sh \
    .tmp/issue-42-bold.md \
    .tmp/issue-42-paranoia.md \
    .tmp/issue-42-critique.md \
    .tmp/issue-42-proposal-reducer.md \
    .tmp/issue-42-code-reducer.md
```

**Script automatically:**
1. Validates all 5 report files exist
2. Extracts issue number from first report filename
3. Combines all 5 reports into debate report
4. Invokes external AI (Codex or Claude Opus)
5. Determines if consensus or multiple options
6. Saves result to consensus file

**Timeout**: 30 minutes (same as external-consensus)

## Error Handling

### Report Files Not Found

```
Error: Report file not found: {file_path}
```

**Solution**: Ensure all 5 agent reports were generated.

### External Reviewer Failure

```
Error: External review failed with exit code {code}
```

**Solution**: Check API credentials, network, or retry.

## Usage Example

```bash
.claude/skills/partial-consensus/scripts/partial-consensus.sh \
    .tmp/issue-15-bold.md \
    .tmp/issue-15-paranoia.md \
    .tmp/issue-15-critique.md \
    .tmp/issue-15-proposal-reducer.md \
    .tmp/issue-15-code-reducer.md
```

**Output on stdout (last line):**
```
.tmp/issue-15-consensus.md
```

## Refine Mode Naming

In refine mode, report files typically use the `issue-refine-{N}-...` prefix, and outputs will match:

```bash
.claude/skills/partial-consensus/scripts/partial-consensus.sh \
    .tmp/issue-refine-15-bold.md \
    .tmp/issue-refine-15-paranoia.md \
    .tmp/issue-refine-15-critique.md \
    .tmp/issue-refine-15-proposal-reducer.md \
    .tmp/issue-refine-15-code-reducer.md
```

Expected output:
```
.tmp/issue-refine-15-consensus.md
```
