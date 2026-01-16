# Partial Consensus Skill

Synthesize consensus plan(s) from multi-agent debate with dual proposers.

## Overview

This skill processes 5 agent reports and produces either a single consensus plan or multiple plan options when proposers fundamentally disagree.

## Files

| File | Description |
|------|-------------|
| `SKILL.md` | Skill definition and workflow instructions |
| `partial-review-prompt.md` | Prompt template for external AI review |
| `scripts/partial-consensus.sh` | Script to combine reports and invoke external review |

## Usage

```
Skill tool parameters:
  skill: "mega-planner:partial-consensus"
  args: "<bold> <paranoia> <critique> <proposal-reducer> <code-reducer>"
```

## Inputs

Requires 5 agent report file paths:
1. Bold proposer report
2. Paranoia proposer report
3. Critique report
4. Proposal reducer report
5. Code reducer report

## Outputs

- `.tmp/issue-{N}-debate.md` - Combined debate report
- `.tmp/issue-{N}-consensus.md` - Final plan(s)

## See Also

- `/mega-planner` command: `.claude/commands/mega-planner.md`
- Agents: `.claude/agents/`
