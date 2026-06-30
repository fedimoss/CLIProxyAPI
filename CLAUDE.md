@AGENTS.md

<!-- gitnexus:start -->
# GitNexus — Code Intelligence

This project is indexed by GitNexus as **CLIProxyAPI** (28303 symbols, 88095 relationships, 300 execution flows). Use the GitNexus MCP tools to understand code, assess impact, and navigate safely.

> If any GitNexus tool warns the index is stale, run `npx gitnexus analyze` in terminal first.

## Always Do

- **MUST run impact analysis before editing any symbol.** Before modifying a function, class, or method, run `gitnexus_impact({target: "symbolName", direction: "upstream"})` and report the blast radius (direct callers, affected processes, risk level) to the user.
- **MUST run `gitnexus_detect_changes()` before committing** to verify your changes only affect expected symbols and execution flows.
- **MUST warn the user** if impact analysis returns HIGH or CRITICAL risk before proceeding with edits.
- When exploring unfamiliar code, use `gitnexus_query({query: "concept"})` to find execution flows instead of grepping. It returns process-grouped results ranked by relevance.
- When you need full context on a specific symbol — callers, callees, which execution flows it participates in — use `gitnexus_context({name: "symbolName"})`.

## Never Do

- NEVER edit a function, class, or method without first running `gitnexus_impact` on it.
- NEVER ignore HIGH or CRITICAL risk warnings from impact analysis.
- NEVER rename symbols with find-and-replace — use `gitnexus_rename` which understands the call graph.
- NEVER commit changes without running `gitnexus_detect_changes()` to check affected scope.

## Resources

| Resource | Use for |
|----------|---------|
| `gitnexus://repo/CLIProxyAPI/context` | Codebase overview, check index freshness |
| `gitnexus://repo/CLIProxyAPI/clusters` | All functional areas |
| `gitnexus://repo/CLIProxyAPI/processes` | All execution flows |
| `gitnexus://repo/CLIProxyAPI/process/{name}` | Step-by-step execution trace |

## CLI

| Task | Read this skill file |
|------|---------------------|
| Understand architecture / "How does X work?" | `.claude/skills/gitnexus/gitnexus-exploring/SKILL.md` |
| Blast radius / "What breaks if I change X?" | `.claude/skills/gitnexus/gitnexus-impact-analysis/SKILL.md` |
| Trace bugs / "Why is X failing?" | `.claude/skills/gitnexus/gitnexus-debugging/SKILL.md` |
| Rename / extract / split / refactor | `.claude/skills/gitnexus/gitnexus-refactoring/SKILL.md` |
| Tools, resources, schema reference | `.claude/skills/gitnexus/gitnexus-guide/SKILL.md` |
| Index, status, clean, wiki CLI commands | `.claude/skills/gitnexus/gitnexus-cli/SKILL.md` |
| Work in the Executor area (1043 symbols) | `.claude/skills/generated/executor/SKILL.md` |
| Work in the Auth area (643 symbols) | `.claude/skills/generated/auth/SKILL.md` |
| Work in the Pluginhost area (544 symbols) | `.claude/skills/generated/pluginhost/SKILL.md` |
| Work in the Management area (437 symbols) | `.claude/skills/generated/management/SKILL.md` |
| Work in the Openai area (382 symbols) | `.claude/skills/generated/openai/SKILL.md` |
| Work in the Claude area (367 symbols) | `.claude/skills/generated/claude/SKILL.md` |
| Work in the Go area (263 symbols) | `.claude/skills/generated/go/SKILL.md` |
| Work in the Helps area (189 symbols) | `.claude/skills/generated/helps/SKILL.md` |
| Work in the Handlers area (178 symbols) | `.claude/skills/generated/handlers/SKILL.md` |
| Work in the Signature area (138 symbols) | `.claude/skills/generated/signature/SKILL.md` |
| Work in the Tui area (127 symbols) | `.claude/skills/generated/tui/SKILL.md` |
| Work in the Api area (125 symbols) | `.claude/skills/generated/api/SKILL.md` |
| Work in the Responses area (124 symbols) | `.claude/skills/generated/responses/SKILL.md` |
| Work in the Home area (117 symbols) | `.claude/skills/generated/home/SKILL.md` |
| Work in the Gemini area (115 symbols) | `.claude/skills/generated/gemini/SKILL.md` |
| Work in the Store area (115 symbols) | `.claude/skills/generated/store/SKILL.md` |
| Work in the Cliproxy area (112 symbols) | `.claude/skills/generated/cliproxy/SKILL.md` |
| Work in the Logging area (112 symbols) | `.claude/skills/generated/logging/SKILL.md` |
| Work in the Watcher area (108 symbols) | `.claude/skills/generated/watcher/SKILL.md` |
| Work in the Util area (107 symbols) | `.claude/skills/generated/util/SKILL.md` |

<!-- gitnexus:end -->
