---
name: mega-planner
description: Multi-agent debate-based planning with dual proposers (bold + paranoia) and partial consensus
argument-hint: [feature-description] or --refine [issue-no] [refine-comments] or --from-issue [issue-no]
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

2. This command uses a **multi-agent debate system** to generate high-quality plans.
**No matter** how simple you think the request is, always strictly follow the multi-agent
debate workflow below to do a thorough analysis of the request throughout the whole code base.
Sometimes what seems simple at first may have hidden complexities or breaking changes that
need to be uncovered via a debate and thorough codebase analysis.
  - **DO** follow the following multi-agent debate workflow exactly as specified.

Create implementation plans through multi-agent debate, combining innovation, critical analysis,
and simplification into a balanced consensus plan.

Invoke the command: `/mega-planner [feature-description]` or `/mega-planner --refine [issue-no] [refine-comments]`

## What This Command Does

This command orchestrates a multi-agent debate system to generate high-quality implementation plans:

1. **Context gathering**: Launch understander agent to gather codebase context
2. **Dual proposer debate**: Launch bold-proposer and paranoia-proposer in parallel
3. **Three-agent analysis**: Critique and two reducers analyze BOTH proposals
4. **Combine reports**: Merge all perspectives into single document
5. **Partial consensus**: Invoke partial-consensus skill to synthesize balanced plan (or options)
6. **Draft issue creation**: Automatically create draft GitHub issue via open-issue skill

## Inputs

**This command only accepts feature descriptions for planning purposes. It does not execute implementation.**

**Default mode:**
```
/mega-planner Add user authentication with JWT tokens and role-based access control
```

**Refinement mode:**
```
/mega-planner --refine <issue-no> <refine-comments>
```
- Refines an existing plan by running it through the debate system again

**From-issue mode:**
```
/mega-planner --from-issue <issue-no>
```
- Creates a plan for an existing issue (typically a feature request)
- Reads the issue title and body as the feature description
- Updates the existing issue with the consensus plan (no new issue created)
- Used by the server for automatic feature request planning

**From conversation context:**
- If arguments is empty, extract feature description from recent messages
- Look for: "implement...", "add...", "create...", "build..." statements

## Outputs

**This command produces planning documents only. No code changes are made.**

**Files created:**
- `.tmp/issue-[refine-]{N}-context.md` - Understander context summary
- `.tmp/issue-[refine-]{N}-bold.md` - Bold proposer agent report (with code diff drafts)
- `.tmp/issue-[refine-]{N}-paranoia.md` - Paranoia proposer agent report (with code diff drafts)
- `.tmp/issue-[refine-]{N}-critique.md` - Critique agent report (analyzes both proposals)
- `.tmp/issue-[refine-]{N}-proposal-reducer.md` - Proposal reducer report (simplifies both proposals)
- `.tmp/issue-[refine-]{N}-code-reducer.md` - Code reducer report (reduces total code footprint)
- `.tmp/issue-[refine-]{N}-debate.md` - Combined multi-agent report
- `.tmp/issue-[refine-]{N}-consensus.md` - Final plan (or plan options)

`[refine-]` is optional for refine mode.

**GitHub issue:**
- Created via open-issue skill if user approves

**Terminal output:**
- Debate summary from all agents
- Consensus plan summary
- GitHub issue URL (if created)

## Workflow

### Step 1: Parse Arguments and Extract Feature Description

Accept the $ARGUMENTS.

**Refinement mode:** If we have `--refine` at the beginning, the next number is the issue number to be refined,
and the rest are issue refine comments. You should fetch the issue to incorporate the users comments.
```bash
gh issue view <issue-no>
```

**From-issue mode:** If we have `--from-issue` at the beginning, the next number is the issue number to plan.
Fetch the issue title and body to use as the feature description:
```bash
gh issue view <issue-no> --json title,body
```
In this mode:
- The issue number is saved for Step 3 (skip placeholder creation, use existing issue)
- The feature description is extracted from the issue title and body
- After consensus, update the existing issue instead of creating a new one

### Step 2: Validate Feature Description

Ensure feature description is clear and complete:

**Check:**
- Non-empty (minimum 10 characters)
- Describes what to build (not just "add feature")
- Provides enough context for agents to analyze

**If unclear:**
```
The feature description is unclear or too brief.

Current description: {description}

Please provide more details:
- What functionality are you adding?
- What problem does it solve?
- Any specific requirements or constraints?
```

Ask user for clarification.

### Step 3: Create Placeholder Issue (or use existing issue for --from-issue / --refine mode)

**For `--from-issue` mode:**
Skip placeholder creation. Use the issue number from Step 1 as `ISSUE_NUMBER` for all artifact filenames.
Set `FILE_PREFIX="issue-${ISSUE_NUMBER}"`.

**For `--refine` mode:**
Skip placeholder creation. Use the issue number from Step 1 as `ISSUE_NUMBER` for all artifact filenames.
Set `FILE_PREFIX="issue-refine-${ISSUE_NUMBER}"`.

**For default mode (new feature):**

**REQUIRED SKILL CALL (before agent execution):**

Create a placeholder issue to obtain the issue number for artifact naming:
```
Skill tool parameters:
  skill: "open-issue"
  args: "--auto"
```

**Provide context to open-issue skill:**
- Feature description: `FEATURE_DESC`
- Issue body: "Placeholder for multi-agent planning in progress. This will be updated with the consensus plan."

**Extract issue number from response:**
```bash
# Expected output: "GitHub issue created: #42"
ISSUE_URL=$(echo "$OPEN_ISSUE_OUTPUT" | grep -o 'https://[^ ]*')
ISSUE_NUMBER=$(echo "$ISSUE_URL" | grep -o '[0-9]*$')
FILE_PREFIX="issue-${ISSUE_NUMBER}"
```

**Use `FILE_PREFIX` for all artifact filenames going forward** (Steps 4-8).

**Error handling:**
- If placeholder creation fails, stop execution and report error (cannot proceed without issue number)

### Step 4: Invoke Understander Agent

**REQUIRED TOOL CALL:**

```
Task tool parameters:
  subagent_type: "agentize:understander"
  prompt: "Gather codebase context for the following feature request: {FEATURE_DESC}"
  description: "Gather codebase context"
  model: "sonnet"
```

**Wait for agent completion** (blocking operation, do not proceed until done).

**Extract output:**
- Generate filename: `CONTEXT_FILE=".tmp/${FILE_PREFIX}-context.md"`
- Save the agent's full response to `$CONTEXT_FILE`
- Also store in variable `UNDERSTANDER_OUTPUT` for passing to subsequent agents

### Step 5: Invoke Dual Proposers (Bold + Paranoia) in Parallel

**CRITICAL**: Launch BOTH proposers in a SINGLE message with TWO Task tool calls.

**Task tool call #1 - Bold Proposer:**
```
Task tool parameters:
  subagent_type: "mega-planner:bold-proposer"
  prompt: "Research and propose an innovative solution for: {FEATURE_DESC}

CODEBASE CONTEXT (from understander):
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

CODEBASE CONTEXT (from understander):
{UNDERSTANDER_OUTPUT}

IMPORTANT: Instead of LOC estimates, provide CODE DIFF DRAFTS for each component.
Use ```diff blocks to show proposed changes."
  description: "Propose destructive refactoring"
  model: "opus"
```

**Wait for both agents to complete.**

**Extract outputs:**
- Generate filename: `BOLD_FILE=".tmp/${FILE_PREFIX}-bold.md"`
- Save bold proposer's full response to `$BOLD_FILE`
- Also store in variable `BOLD_PROPOSAL`
- Generate filename: `PARANOIA_FILE=".tmp/${FILE_PREFIX}-paranoia.md"`
- Save paranoia proposer's full response to `$PARANOIA_FILE`
- Also store in variable `PARANOIA_PROPOSAL`

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
  subagent_type: "mega-planner:proposal-reducer"
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

**Extract outputs:**
- Generate filename: `CRITIQUE_FILE=".tmp/${FILE_PREFIX}-critique.md"`
- Save critique agent's response to `$CRITIQUE_FILE`
- Generate filename: `PROPOSAL_REDUCER_FILE=".tmp/${FILE_PREFIX}-proposal-reducer.md"`
- Save proposal reducer's response to `$PROPOSAL_REDUCER_FILE`
- Generate filename: `CODE_REDUCER_FILE=".tmp/${FILE_PREFIX}-code-reducer.md"`
- Save code reducer's response to `$CODE_REDUCER_FILE`

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

**Expected outputs:**
- Debate report: `.tmp/${FILE_PREFIX}-debate.md`
- Consensus plan: `.tmp/${FILE_PREFIX}-consensus.md`

**Extract:**
- Save the consensus plan file path as `CONSENSUS_PLAN_FILE=".tmp/${FILE_PREFIX}-consensus.md"`

Give it 30 minutes timeout to complete.

### Step 8: Update Issue with Consensus Plan

**REQUIRED SKILL CALL:**

```
Skill tool parameters:
  skill: "open-issue"
  args: "--update ${ISSUE_NUMBER} --auto {CONSENSUS_PLAN_FILE}"
```

**What this skill does:**
1. Reads consensus plan from file
2. Determines appropriate tag from `docs/git-msg-tags.md`
3. Formats issue with `[plan]` prefix and Problem Statement/Proposed Solution sections
4. Updates existing issue #${ISSUE_NUMBER} using `gh issue edit`
5. Returns issue number and URL

**If multiple plans were generated (no consensus):**
- Present all options to user
- Let user select preferred approach
- Update issue with selected plan

**Expected output:**
```
Plan issue #${ISSUE_NUMBER} updated with consensus plan.

Title: [plan][tag] {feature name}
URL: {issue_url}

To refine: /mega-planner --refine ${ISSUE_NUMBER}
To implement: /issue-to-impl ${ISSUE_NUMBER}
```

### Step 9: Finalize Issue Labels

```bash
gh issue edit ${ISSUE_NUMBER} --add-label "agentize:plan"
```

**For `--from-issue` mode only:** Also remove the "agentize:feat-request" label if present:

```bash
gh issue edit ${ISSUE_NUMBER} --remove-label "agentize:feat-request"
```

**Expected output:**
```
Label "agentize:plan" added to issue #${ISSUE_NUMBER}
```

Display the final output to the user. Command completes successfully.

-------------

Follow the workflow and $ARGUMENT parsing above to make the plan.

$ARGUMENTS
