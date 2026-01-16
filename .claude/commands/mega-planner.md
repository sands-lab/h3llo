---
name: mega-planner
description: Multi-agent debate-based planning with dual proposers (bold + paranoia) and partial consensus
argument-hint: [feature-description] or --force-full [feature-description] or --refine [issue-no] [refine-comments] or --from-issue [issue-no]
---

# Mega Planner Command

**IMPORTANT**: Keep a correct mindset when this command is invoked.

0. This workflow is intended to be as hands-off as possible, do your best
  - NOT TO STOP until the plan is finalized
  - NOT TO ask user for design decisions. Choose the one you think the most reasonable.
    If it is bad plan, user will feed it later.

1. This is a **planning workflow**. It takes a feature description as input and produces
a consensus implementation plan as output. It does NOT make any code changes or implement features.
Even if user is telling you "build...", "add...", "create...", "implement...", or "fix...",
you must interpret these as making a plan for how to have these achieved, not actually doing them!
  - **DO NOT** make any changes to the codebase!

2. This command uses a **multi-agent debate system** with **dual proposers** to generate high-quality plans.
**No matter** how simple you think the request is, always strictly follow the multi-agent
debate workflow below to do a thorough analysis of the request throughout the whole code base.

## Key Differences from Ultra-Planner

| Aspect | Ultra-Planner | Mega-Planner |
|--------|---------------|--------------|
| Proposers | 1 (bold-proposer) | 2 (bold-proposer + paranoia-proposer) |
| Proposal Output | LOC estimates | **Code diff drafts** |
| Reducers | 1 (proposal-reducer) | 2 (proposal-reducer + code-reducer) |
| Critique Scope | Analyzes bold only | Analyzes **both** proposers |
| Consensus | Single consensus | **Partial consensus** (multiple options if no agreement) |

## What This Command Does

This command orchestrates a multi-agent debate system with dual proposers:

1. **Context gathering**: Launch understander agent to gather codebase context
2. **Dual proposer debate**: Launch bold-proposer AND paranoia-proposer in parallel
3. **Four-agent analysis**: Critique and both reducers analyze BOTH proposals
4. **Combine reports**: Merge all perspectives into single document
5. **Partial consensus**: Invoke partial-consensus skill to synthesize balanced plan(s)
6. **Draft issue creation**: Automatically create draft GitHub issue via open-issue skill

## Inputs

**This command only accepts feature descriptions for planning purposes. It does not execute implementation.**

**Default mode:**
```
/mega-planner Add user authentication with JWT tokens and role-based access control
```

**Refinement mode:**
```
/mega-planner --refine <issue-no> <description>
```

**From-issue mode:**
```
/mega-planner --from-issue <issue-no>
```

**From conversation context:**
- If arguments is empty, extract feature description from recent messages

## Outputs

**This command produces planning documents only. No code changes are made.**

**Files created:**
- `.tmp/issue-{N}-context.md` - Understander context summary
- `.tmp/issue-{N}-bold.md` - Bold proposer agent report (with code diffs)
- `.tmp/issue-{N}-paranoia.md` - Paranoia proposer agent report (with code diffs)
- `.tmp/issue-{N}-critique.md` - Critique agent report (analyzes both)
- `.tmp/issue-{N}-proposal-reducer.md` - Proposal reducer report
- `.tmp/issue-{N}-code-reducer.md` - Code reducer report
- `.tmp/issue-{N}-debate.md` - Combined multi-agent report
- `.tmp/issue-{N}-consensus.md` - Final balanced plan(s)

## Workflow

### Step 1: Parse Arguments and Extract Feature Description

Accept the $ARGUMENTS.

**Force-full mode:** If we have `--force-full` at the beginning, skip complexity-based routing and always use the full multi-agent debate path.

**Refinement mode:** If we have `--refine` at the beginning, the next number is the issue number to be refined.
```bash
gh issue view <issue-no>
```

**From-issue mode:** If we have `--from-issue` at the beginning, the next number is the issue number to plan.
```bash
gh issue view <issue-no> --json title,body
```

### Step 2: Validate Feature Description

Ensure feature description is clear and complete:

**Check:**
- Non-empty (minimum 10 characters)
- Describes what to build (not just "add feature")
- Provides enough context for agents to analyze

**If unclear:** Ask user for clarification.

### Step 3: Create Placeholder Issue

**For `--from-issue` mode:** Skip placeholder creation. Use the existing issue number.

**For default mode (new feature):**

```
Skill tool parameters:
  skill: "open-issue"
  args: "--auto"
```

Extract issue number from response and use `ISSUE_NUMBER` for all artifact filenames.

### Step 4: Invoke Understander Agent

**REQUIRED TOOL CALL:**

```
Task tool parameters:
  subagent_type: "agentize:understander"
  prompt: "Gather codebase context for: {FEATURE_DESC}"
  description: "Gather codebase context"
  model: "sonnet"
```

Save output to `.tmp/issue-${ISSUE_NUMBER}-context.md`.

### Step 5: Invoke Dual Proposers (Bold + Paranoia) in Parallel

**CRITICAL**: Launch BOTH proposers in a SINGLE message with TWO Task tool calls.

**Task tool call #1 - Bold Proposer:**
```
Task tool parameters:
  subagent_type: "mega-planner:bold-proposer"
  prompt: "Research and propose an innovative solution for: {FEATURE_DESC}

CODEBASE CONTEXT:
{UNDERSTANDER_OUTPUT}

IMPORTANT: Instead of LOC estimates, provide CODE DIFF DRAFTS for each component.
Use ```diff blocks to show proposed changes."
  description: "Research SOTA solutions"
  model: "opus"
```

**Task tool call #2 - Paranoia Proposer:**
```
Task tool parameters:
  subagent_type: "mega-planner:paranoia-proposer"
  prompt: "Critically analyze and propose a destructive refactoring solution for: {FEATURE_DESC}

CODEBASE CONTEXT:
{UNDERSTANDER_OUTPUT}

IMPORTANT: Instead of LOC estimates, provide CODE DIFF DRAFTS for each component.
Use ```diff blocks to show proposed changes."
  description: "Propose destructive refactoring"
  model: "opus"
```

**Wait for both agents to complete.**

Save outputs:
- Bold: `.tmp/issue-${ISSUE_NUMBER}-bold.md`
- Paranoia: `.tmp/issue-${ISSUE_NUMBER}-paranoia.md`

### Step 6: Invoke Critique and Both Reducers in Parallel

**CRITICAL**: Launch ALL THREE agents in a SINGLE message with THREE Task tool calls.

**Task tool call #1 - Critique Agent:**
```
Task tool parameters:
  subagent_type: "mega-planner:proposal-critique"
  prompt: "Analyze BOTH proposals for feasibility and risks:

Feature: {FEATURE_DESC}

BOLD PROPOSAL:
{BOLD_PROPOSAL}

PARANOIA PROPOSAL:
{PARANOIA_PROPOSAL}

Compare both approaches and provide critical analysis."
  description: "Critique both proposals"
  model: "opus"
```

**Task tool call #2 - Proposal Reducer:**
```
Task tool parameters:
  subagent_type: "agentize:proposal-reducer"
  prompt: "Simplify BOTH proposals using 'less is more' philosophy:

Feature: {FEATURE_DESC}

BOLD PROPOSAL:
{BOLD_PROPOSAL}

PARANOIA PROPOSAL:
{PARANOIA_PROPOSAL}

Identify unnecessary complexity in both and propose simpler alternatives."
  description: "Simplify both proposals"
  model: "opus"
```

**Task tool call #3 - Code Reducer:**
```
Task tool parameters:
  subagent_type: "mega-planner:code-reducer"
  prompt: "Analyze code changes in BOTH proposals:

Feature: {FEATURE_DESC}

BOLD PROPOSAL:
{BOLD_PROPOSAL}

PARANOIA PROPOSAL:
{PARANOIA_PROPOSAL}

Focus on reducing total code footprint while allowing large changes."
  description: "Reduce code complexity"
  model: "opus"
```

**Wait for all three agents to complete.**

Save outputs:
- Critique: `.tmp/issue-${ISSUE_NUMBER}-critique.md`
- Proposal Reducer: `.tmp/issue-${ISSUE_NUMBER}-proposal-reducer.md`
- Code Reducer: `.tmp/issue-${ISSUE_NUMBER}-code-reducer.md`

### Step 7: Invoke Partial Consensus Skill

**REQUIRED SKILL CALL:**

```
Skill tool parameters:
  skill: "mega-planner:partial-consensus"
  args: "{BOLD_FILE} {PARANOIA_FILE} {CRITIQUE_FILE} {PROPOSAL_REDUCER_FILE} {CODE_REDUCER_FILE}"
```

**What this skill does:**
1. Combines all 5 agent reports into a single debate report
2. Processes through external AI review
3. **If consensus reached**: Produces single balanced plan
4. **If no consensus**: Produces multiple plan options for user selection

Give it 30 minutes timeout to complete.

### Step 8: Update Issue with Consensus Plan

**REQUIRED SKILL CALL:**

```
Skill tool parameters:
  skill: "open-issue"
  args: "--update ${ISSUE_NUMBER} --auto {CONSENSUS_PLAN_FILE}"
```

**If multiple plans were generated (no consensus):**
- Present all options to user
- Let user select preferred approach
- Update issue with selected plan

### Step 9: Finalize Issue Labels

```bash
gh issue edit ${ISSUE_NUMBER} --add-label "agentize:plan"
```

Display the final output to the user. Command completes successfully.

-------------

Follow the workflow and $ARGUMENT parsing above to make the plan.

$ARGUMENTS
