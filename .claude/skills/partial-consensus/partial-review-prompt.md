# Partial Consensus Review Task

You are an expert software architect tasked with synthesizing implementation plan(s) from a **dual-proposer debate** with five different perspectives.

## Context

Five specialized agents have analyzed the following requirement:

**Feature Request**: {{FEATURE_DESCRIPTION}}

Each agent provided a different perspective:
1. **Bold Proposer**: Innovative, SOTA-driven approach (builds on existing code)
2. **Paranoia Proposer**: Destructive refactoring approach (tears down and rebuilds)
3. **Critique Agent**: Feasibility analysis of BOTH proposals
4. **Proposal Reducer**: Simplification of BOTH proposals (minimizes change scope)
5. **Code Reducer**: Code footprint analysis (minimizes total code)

## Your Task

Review all five perspectives and determine if consensus is possible:

**If consensus IS possible:**
- Synthesize a single balanced implementation plan
- Incorporate the best ideas from both proposers
- Address risks from critique
- Apply simplifications from both reducers

**If consensus is NOT possible:**
- Generate THREE separate plan options (Option A, B, and C)
- Option A: Conservative - Lower risk, incremental changes, minimal disruption
- Option B: Aggressive - Higher risk, significant refactoring, maximum improvement
- Option C: Balanced - Synthesizes best elements from both proposers with moderate trade-offs
- Each option should be derived from whichever proposer(s) best support that approach
- Include comparison table and recommendation

## Refutation Requirements for Synthesis

**CRITICAL**: When reconciling conflicting proposals, disagreements MUST be resolved with evidence.

### Rule 1: Cite Both Sides

When proposals disagree, document both positions before deciding:

```
### Disagreement: [Topic]

**Bold claims**: [Quote from bold proposal]
**Paranoia claims**: [Quote from paranoia proposal]
**Critique says**: [What critique agent found]
**Resolution**: [Which side is adopted and why, with evidence]
```

### Rule 2: No Silent Rejection

If dropping an idea from either proposal:
1. Explicitly state what is being dropped
2. Cite the evidence for dropping it (from critique or reducers)
3. Note any trade-offs accepted

**Example:**
```
**Dropped from Bold**: "Automatic retry with exponential backoff"
**Reason**: Critique identified this adds 80 LOC for edge case occurring <0.1% of requests
**Trade-off**: Manual retry required for transient failures (acceptable per requirements)
```

### Rule 3: Hybrid Must Justify Both Sources

If combining elements from both proposals:
```
**From Bold**: [Element] - Why: [Justification]
**From Paranoia**: [Element] - Why: [Justification]
**Integration**: [How they work together]
```

### Evidence Requirements for Options

Each option MUST include:
1. **Source attribution**: Which proposer(s) this option derives from
2. **Evidence for viability**: Cite specific critique/reducer findings
3. **Trade-off acknowledgment**: What is sacrificed and why it's acceptable

Options without this evidence are invalid.

## Input: Combined Report

Below is the combined report containing all five perspectives:

---

{{COMBINED_REPORT}}

---

## Output Requirements

### Format A: Single Consensus Plan

Use this format when the proposals can be reconciled:

```markdown
# Implementation Plan: {{FEATURE_NAME}}

## Consensus Summary
[How the proposals were reconciled]

## Goal
[Problem statement]

**Success criteria:**
- [Criterion 1]

**Out of scope:**
- [What we're not doing]

## Codebase Analysis

**File changes:**

| File | Level | Purpose |
|------|-------|---------|
| `path/to/file` | major/medium/minor/remove | Description |

## Implementation Steps

**Step 1: [Description]**
- File changes
- Code diff (if applicable)

## Success Criteria

- [ ] Criterion 1

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Risk 1 | H/M/L | H/M/L | Mitigation |
```

### Format B: Multiple Options (No Consensus)

Use this format when proposals are fundamentally incompatible:

```markdown
# Implementation Options: {{FEATURE_NAME}}

## Why No Consensus

[Explain the fundamental disagreement between Bold and Paranoia]

## Option A: Conservative Approach

### Summary
[Lower risk, incremental changes, minimal disruption. Derived from whichever proposer(s) support this approach.]

### File Changes
| File | Level | Purpose |
|------|-------|---------|
| ... | ... | ... |

### Key Code Changes
```diff
[Code diff - minimal, safe changes]
```

## Option B: Aggressive Approach

### Summary
[Higher risk, significant refactoring, maximum improvement. Derived from whichever proposer(s) support this approach.]

### File Changes
| File | Level | Purpose |
|------|-------|---------|
| ... | ... | ... |

### Key Code Changes
```diff
[Code diff - aggressive refactoring]
```

## Option C: Balanced Approach

### Summary
[Moderate risk, synthesizes best elements from both proposers. Balances improvement against disruption.]

### File Changes
| File | Level | Purpose |
|------|-------|---------|
| ... | ... | ... |

### Key Code Changes
```diff
[Code diff - balanced approach]
```

## Comparison

| Aspect | Option A (Conservative) | Option B (Aggressive) | Option C (Balanced) |
|--------|-------------------------|----------------------|---------------------|
| Risk level | Low | High | Medium |
| Code reduction | Minimal | Maximum | Moderate |
| Breaking changes | Few/None | Many | Some |
| Implementation effort | Low | High | Medium |
| Long-term maintainability | Good | Best | Better |
| Innovation | Low | High | Medium |

## Recommendation

**Recommended option**: [A, B, or C]

**Rationale**: [Why this option is recommended for this specific case]

**When to choose other options**:
- Choose A if: [Conditions favoring conservative approach]
- Choose B if: [Conditions favoring aggressive approach]
- Choose C if: [Conditions favoring balanced approach]
```

## Decision Criteria

Choose **Format A (Single Consensus)** when:
- Both proposals agree on core architecture
- Differences are in implementation details only
- Critique validates both approaches as feasible

Choose **Format B (Multiple Options)** when:
- Proposals have fundamentally different architectures
- One proposes incremental change, other proposes rewrite
- Trade-offs are significant and user preference matters

## Privacy Note

Ensure no sensitive information is included:
- No absolute paths from `/` or `~`
- No API keys or credentials
- No personal data
