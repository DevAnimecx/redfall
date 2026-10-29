---
title: Bring your own agent
seoTitle: "RedFall Agents: Drive It With Claude Code or Codex"
description: "RedFall needs no AI API key. Drive it with an installed agent — Claude Code, Codex, Gemini CLI, Cursor, Aider and seven more — or an OpenAI-compatible endpoint."
path: docs/agents/
group: How it works
kind: pillar
pillar: agents
order: 4
updated: 2026-10-29
keywords: vulnerability scanner without api key, claude code security scanner, codex vulnerability scanning, bring your own agent, local llm security scanner
sources: https://github.com/DevAnimecx/redfall, https://docs.litellm.ai/
related: architecture, interop, sandbox
---

RedFall 0.1.x required a provider API key. From **0.2.0 it does not.** The engine
reasons through one interface — `ReasoningBackend` — and one implementation of
that interface is an agent you already run. A provider key is now one option
among several rather than a requirement.

This is the same design decision as the rest of RedFall: the model is rented and
replaceable, so the engine must not be welded to any one way of getting an
answer. What changes between backends is who reasons; what stays the same is the
code graph, the sandbox, the proof and the repair.

## The four backends

| `kind` | What it is | Needs |
| --- | --- | --- |
| `agent` | An installed agent RedFall drives over its own CLI | The agent on `PATH` |
| `litellm` | The original BYOK path | A provider key |
| `openai_compat` | Any OpenAI-compatible endpoint — Ollama, vLLM, LM Studio, OpenRouter, a gateway | A base URL, optionally a key |
| `router` | Several backends, chosen per tier, or a consensus across agents | At least one route or a consensus list |

`kind = "auto"` (the default) prefers a provider key if one is set, otherwise
the first detected agent. When neither is present it **refuses and names both
options** — it does not fall back to something weaker, because a scan whose
quality depends on which agents happened to be installed would produce findings
nobody could reproduce.

## The twelve supported agents

`claude-code`, `codex`, `gemini-cli`, `aider`, `cursor`, `goose`, `openhands`,
`continue`, `cline`, `kilo`, `qwen-code`, `crush`.

Each driver runs the agent's real non-interactive entry point. Detection is by
executable, and every driver accepts a `REDFALL_*_BIN` environment override for
a non-`PATH` install.

```
$ redfall agent list
$ redfall agent detect        # which backend `auto` would use on this host
$ redfall agent certify codex # run it for real and record what it proved
```

`certify` is the same discipline as `redfall mcp certify`: a real process, one
real task, one refusal case. It records four checks — installed, answers,
returns parseable JSON, exits cleanly — and reports `certified: true` only when
all four pass. A certification covers this agent, this version, on this host, at
this time. It is not a claim about the agent in general.

## An agent RedFall has never heard of

The custom driver is the escape hatch, and it is what makes "12 supported" a
floor rather than a ceiling. Describe the command in `redfall.toml` and it
behaves like any shipped driver:

```toml
[[backend.options.agents]]
name = "my-agent"
command = "my-agent-cli"
args = ["--prompt", "{prompt}"]     # or omit args to pass the prompt on stdin
env = { MY_AGENT_KEY = "MY_AGENT_KEY" }
json_path = "result.content"        # optional: where the reply lives in stdout
```

`command` is executed **directly, never through a shell**, so `args` cannot
inject a shell command — and a prompt containing shell metacharacters reaches
the agent as one literal argv element. This matters: prompts carry the target's
source, and the target's source is untrusted.

## Routing and consensus

Route by tier so cheap work stays cheap:

```toml
[routes]
fast = { kind = "agent", agent = "gemini-cli" }
deep = { kind = "agent", agent = "claude-code" }
```

Or take a consensus, where a finding survives only if at least `min_agree`
agents produced the same parsed JSON:

```toml
[consensus]
agents = ["claude-code", "codex"]
min_agree = 2
```

**Agreement is a prior, never proof.** A finding that every agent agrees on is
still executed in the sandbox, and only a reproduction makes it a finding.
Consensus reduces wasted sandbox time; it does not replace verification.

## What does not change

An agent answers the same prompts a model would, and its answers are held to the
same standard:

- every call is recorded in the same `LLMCall` / `LLMResponse` transcript tables
  a provider call uses, so a finding produced by Claude Code is as replayable as
  one produced by a hosted model;
- the budget is enforced before each call, so an over-budget campaign fails
  rather than silently truncating;
- malformed JSON is re-prompted, and a backend that never returns valid JSON
  raises rather than inventing a default;
- a finding is still only real when the sandbox reproduces it, so a host without
  a container runtime still refuses to scan.
