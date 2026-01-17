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

This skill synthesizes implementation plan(s) from a multi-agent debate with dual proposers. Unlike external-consensus which always produces a single plan, this skill can produce **multiple plan options** when the proposers fundamentally disagree.

## Key Difference from External Consensus

| Aspect | External Consensus | Partial Consensus |
|--------|-------------------|-------------------|
| Input | 3 reports (bold, critique, reducer) | 5 reports (bold, paranoia, critique, proposal-reducer, code-reducer) |
| Output | Always single consensus | Single OR multiple options |
| Philosophy | Force agreement | Allow disagreement |

## When Multiple Options Are Generated

The skill produces multiple plans when:
1. Bold and Paranoia propose fundamentally different architectures
2. Critique identifies valid points for BOTH approaches
3. Code-reducer recommends different approaches for different goals

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

**Output format when consensus reached:**
```markdown
# Implementation Plan: {Feature Name}
[Single balanced plan...]
```

**Output format when NO consensus (multiple options):**
```markdown
# Implementation Options: {Feature Name}

## Option A: Conservative Approach (Bold-based)
[Plan based on Bold proposal...]

## Option B: Aggressive Approach (Paranoia-based)
[Plan based on Paranoia proposal...]

## Comparison
| Aspect | Option A | Option B |
|--------|----------|----------|
| Risk | Lower | Higher |
| Code reduction | Moderate | Aggressive |
| Breaking changes | Few | Many |

## Recommendation
[Which option is recommended and why]
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
