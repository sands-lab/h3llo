# Skills

This directory contains reusable skills for Claude Code commands and agents.

## Available Skills

| Skill | Description |
|-------|-------------|
| `partial-consensus` | Synthesize consensus plan(s) from multi-agent debate reports |

## Skill Structure

Each skill is a directory containing:
- `SKILL.md` - Skill definition and instructions
- `scripts/` - Supporting scripts (optional)

## Usage

Skills are invoked via the Skill tool:

```
Skill tool parameters:
  skill: "mega-planner:partial-consensus"
  args: "<bold-file> <paranoia-file> <critique-file> ..."
```

## See Also

- Commands: `.claude/commands/`
- Agents: `.claude/agents/`
