---
name: partial-consensus
description: Determine consensus/disagreement from 5-agent debate - exposes disagreements as developer decisions
allowed-tools:
  - Bash(.claude/skills/partial-consensus/scripts/partial-consensus.sh:*)
  - Bash(cat:*)
  - Bash(test:*)
  - Bash(wc:*)
  - Bash(grep:*)
---

# Partial Consensus Skill

This skill determines consensus and exposes disagreements from a multi-agent debate with dual proposers.

## Consensus Definition

**CONSENSUS** requires ALL of the following:
1. Bold and Paranoia propose the same general approach
2. Critique finds no critical blockers
3. Both Reducers recommend the same base proposal without fundamental changes

**DISAGREEMENT** is triggered by ANY of the following:
1. Bold and Paranoia propose different architectural approaches
2. Critique favors one proposal over another
3. Either Reducer recommends fundamental changes

**Note:** The reviewer uses judgment for ambiguous cases, with optional reference to ~30% LOC delta as "fundamental change" guidance.

## Modes

1. **Standard mode**: Determines consensus/disagreement, generates options for disagreements
2. **Resolve mode**: Same 5 reports but with "User Resolution" section appended, produces unified plan

## Key Features

- **No Silent Resolution**: Disagreements are exposed, not auto-resolved
- **Flexible Options**: Minimum 2, recommended 3, no upper limit per disagreement
- **Source Attribution**: Each option must cite its source (Bold, Paranoia, Hybrid, etc.)
- **AI Recommendations**: Included without disclaimer
- **Collapsible Code Drafts**: `<details>` tags for implementation details

## When Disagreement Sections Are Generated

The skill includes disagreement sections when:
1. Bold and Paranoia propose different approaches to the same sub-problem
2. Critique identifies valid arguments for both positions
3. The choice materially affects implementation

## Inputs

This skill requires exactly 5 agent report file paths:
- **Report 1**: Bold proposer report (`.tmp/issue-{N}-bold.md`)
- **Report 2**: Paranoia proposer report (`.tmp/issue-{N}-paranoia.md`)
- **Report 3**: Critique report (`.tmp/issue-{N}-critique.md`)
- **Report 4**: Proposal reducer report (`.tmp/issue-{N}-proposal-reducer.md`)
- **Report 5**: Code reducer report (`.tmp/issue-{N}-code-reducer.md`)

**For resolve mode:** The bold report should have a `## User Resolution` section appended
containing the user's option selections. The `mega-planner --resolve` command handles this
automatically.

## Outputs

**Files created:**
- `.tmp/issue-{N}-debate.md` - Combined 5-agent debate report
- `.tmp/issue-{N}-consensus.md` - Final plan(s)

**Output format (unified):**
```markdown
# Implementation Plan: {Feature Name}

## Agent Perspectives Summary

| Agent | Core Position | Key Insight |
|-------|---------------|-------------|
| **Bold** | ... | ... |
| **Paranoia** | ... | ... |
| **Critique** | ... | ... |
| **Proposal Reducer** | ... | ... |
| **Code Reducer** | ... | ... |

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
