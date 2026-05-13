# Brain — Phase 5

LLM-powered attack-path reasoning. Takes the serialized graph (from Phase 4)
and the posture findings (from Phase 3), feeds them to **Claude**, and emits
a structured threat report.

This is the only module in BreakBot that makes a network call to a
non-AWS service. It does not touch AWS at all.

---

## The Library — Anthropic Python SDK

We use the official `anthropic` Python SDK to talk to Claude.

```
pip install 'breakbot[llm]'      # installs anthropic>=0.25
export ANTHROPIC_API_KEY=sk-...  # required at runtime
```

### Why Claude (and not a deterministic rule engine)

Posture checks already produce flag-based findings ("SG opens SSH to 0.0.0.0/0").
What they cannot do is *chain* findings together into an actual attack story:

```
"The public ALB → web SG → EC2 instance with IMDSv1 → instance profile
 with s3:* on customer-data → exfiltration"
```

Chaining is multi-hop, context-dependent reasoning. That is what an LLM
is for. Claude reads the serialized graph + posture findings and produces
prioritized attack paths an attacker would actually walk.

### Why `claude-opus-4-7`

| Need                                          | Why Opus 4.7 |
|-----------------------------------------------|--------------|
| Multi-hop reasoning over a dependency graph   | Strongest reasoning tier |
| Handle large attack surfaces (1M-token ctx)   | 1M context window — full graph + posture findings fit easily |
| Self-modulated reasoning depth                | Adaptive thinking — Claude decides how deep to think |
| Structured JSON output                        | Schema adherence is reliable on Opus tier |

---

## SDK Features We Use

```
┌──────────────────────────────────────────────────────────────────┐
│  client.messages.stream(...)                                     │
│  ├── model="claude-opus-4-7"                                     │
│  ├── thinking={"type": "adaptive"}        ← variable reasoning   │
│  ├── tools=[ANALYSIS_TOOL]                ← schema-enforced out  │
│  ├── tool_choice={"type":"tool",                                 │
│  │                "name":"record_security_analysis"}  ← forced   │
│  ├── system=[{                                                   │
│  │     "text": <system prompt>,                                  │
│  │     "cache_control": {"type":"ephemeral"}  ← prefix cache     │
│  │   }]                                                          │
│  ├── messages=[{"role":"user", "content":...}]                   │
│  └── max_tokens=8192                                             │
│                                                                  │
│  with ... as stream:                                             │
│      message = stream.get_final_message()                        │
└──────────────────────────────────────────────────────────────────┘
```

### 1. Streaming

```python
with self._client.messages.stream(...) as stream:
    message = stream.get_final_message()
```

The graph serialization for a real account can be 50K+ tokens of input, and
adaptive thinking can spend tens of thousands of tokens reasoning. A
non-streaming request would hit the SDK's default request timeout.

Streaming keeps the HTTP connection alive and `get_final_message()` waits
until the full response is assembled — same API ergonomics, no timeout risk.

### 2. Adaptive thinking

```python
thinking={"type": "adaptive"}
```

Claude decides on its own how many reasoning tokens to spend before answering.
- Simple graph with one obvious path: light thinking
- Complex graph with overlapping paths and lateral movement: deep thinking

This is the right primitive for attack-path analysis because the work is
**variable**: a 5-resource scan needs different reasoning than a 5,000-resource
scan. A fixed `budget_tokens` would either waste tokens on easy cases or run
short on hard ones.

### 3. Prompt caching

```python
system=[{
    "type": "text",
    "text": _SYSTEM_PROMPT,
    "cache_control": {"type": "ephemeral"},
}]
```

The system prompt (the analyst's "job description" + output JSON schema) is
**large and stable** — it never changes between scans. The user message (the
actual graph + findings) is **unique per scan**.

`cache_control` on the system block tells Anthropic to cache that prefix.
Subsequent runs against the same prompt skip re-tokenizing it. Cost reduction
is substantial on repeat runs.

### 4. Forced tool use (schema-enforced output)

This is the key reliability primitive. Instead of asking Claude *in prose*
to return JSON and then parsing the response with `json.loads`, we define a
tool with a strict JSON-schema and force Claude to call it:

```python
tools=[ANALYSIS_TOOL]
tool_choice={"type": "tool", "name": "record_security_analysis"}
```

When `tool_choice` names a specific tool, the API **guarantees** that:

1. Claude will invoke that tool exactly once.
2. The tool's `input` will validate against the schema **before** the response
   is returned. Missing required fields, wrong enum values, or extra
   properties are rejected server-side.

This means we never:
- ask the model "please respond with valid JSON"
- strip ` ```json ... ``` ` code fences
- catch `JSONDecodeError` and degrade gracefully
- worry about a missing field at parse time

If Claude gets confused and emits anything but our tool call, we raise loudly
(`RuntimeError`) instead of silently returning a half-baked report.

```
        Prompt-only JSON (old)              Tool use (new)
        ─────────────────────              ──────────────
        "Return JSON like this:           tools=[ANALYSIS_TOOL]
         {scan_summary: ..., ...}"        tool_choice={force tool}
                                                  │
            Claude returns                        ▼
            text + maybe ```fences```      API validates schema
                  │                        before sending response
                  ▼                                │
            regex strip fences                    ▼
                  │                        message.content =
                  ▼                          [ThinkingBlock, ...,
            json.loads ── may fail           ToolUseBlock(
                  │                            input={ validated })]
                  ▼                                │
            try/except + defaults                 ▼
                                            tool_input → dataclass
                                            (no parsing, no try/except)
```

### 5. Content block extraction

Adaptive thinking + forced tool use produces a response like:

```
message.content = [
    ThinkingBlock(...),                       ← reasoning, ignored
    ToolUseBlock(
        name="record_security_analysis",
        input={ scan_summary, overall_severity, ... }  ← validated dict
    ),
]
```

`_extract_tool_input()` finds the `ToolUseBlock` with our tool's name and
returns `block.input` directly. No text parsing happens anywhere in this
module.

---

## The Analyst Class

[analyst.py](analyst.py) — the single class that does the work.

```python
from breakbot.brain import SecurityAnalyst

analyst = SecurityAnalyst()              # reads ANTHROPIC_API_KEY from env
report  = analyst.analyze(
    attack_surface,    # str — from GraphSerializer.serialize()
    posture_findings,  # list[dict] — from posture.json
)

print(report.to_markdown())
report.to_json()
report.attack_paths    # list[AttackPath]
```

### Flow

```
                 ┌──────────────────────────────────────┐
                 │ attack_surface.txt   posture.json    │
                 │ (Phase 4 output)      (Phase 3)      │
                 └──────────────────────────────────────┘
                                  │
                                  ▼
                  ┌───────────────────────────────┐
                  │ _build_user_message()         │
                  │  - Group findings by severity │
                  │  - Append graph text          │
                  └───────────────────────────────┘
                                  │
                                  ▼
              ┌─────────────────────────────────────────┐
              │ client.messages.stream(                 │
              │   model="claude-opus-4-7",              │
              │   system=[CACHED_SYSTEM_PROMPT],        │
              │   thinking={"type":"adaptive"},         │
              │   tools=[ANALYSIS_TOOL],                │
              │   tool_choice={force tool},             │
              │   messages=[user_message],              │
              │ )                                       │
              └─────────────────────────────────────────┘
                                  │
                                  ▼
              ┌─────────────────────────────────────────┐
              │ API server-side: validate Claude's      │
              │ tool input against the schema           │
              └─────────────────────────────────────────┘
                                  │
                                  ▼
              ┌─────────────────────────────────────────┐
              │ stream.get_final_message().content      │
              │                                         │
              │   [ThinkingBlock,                       │
              │    ToolUseBlock(input={ validated })]   │
              └─────────────────────────────────────────┘
                                  │
                                  ▼
                  ┌───────────────────────────────┐
                  │ _extract_tool_input() — find  │
                  │ ToolUseBlock, return .input   │
                  └───────────────────────────────┘
                                  │
                                  ▼
                  ┌───────────────────────────────┐
                  │ _build_report() — dataclass   │
                  │ construction (no parsing)     │
                  └───────────────────────────────┘
```

---

## The Prompt

The system prompt does three things:

```
1. Role definition       → "You are a senior cloud security analyst..."
2. Reasoning guidance    → severity scoring, confidence levels,
                           weak-link analysis, behavioral vs. static
3. Output instruction    → "Call the record_security_analysis tool exactly once"
```

The output **schema** is no longer in the prompt at all — it lives in the
tool definition (`_ANALYSIS_TOOL` in [analyst.py](analyst.py)) where the API
can enforce it.

### Tool schema (enforced server-side)

```jsonc
{
  "name": "record_security_analysis",
  "input_schema": {
    "type": "object",
    "properties": {
      "scan_summary":     { "type": "string" },
      "overall_severity": { "enum": ["CRITICAL","HIGH","MEDIUM","LOW"] },
      "attack_paths": {
        "type": "array",
        "maxItems": 10,
        "items": {
          "type": "object",
          "properties": {
            "entry_point":   { "type": "string" },
            "attack_steps":  { "type": "array", "items": {"type":"string"}, "minItems": 1 },
            "blast_radius":  { "type": "string" },
            "severity":      { "enum": ["CRITICAL","HIGH","MEDIUM","LOW"] },
            "confidence":    { "enum": ["HIGH","MEDIUM","LOW"] },
            "remediation":   { "type": "array", "items": {"type":"string"}, "minItems": 1 }
          },
          "required": [ /* all of the above */ ],
          "additionalProperties": false
        }
      },
      "top_risks": { "type": "array", "items": {"type":"string"} }
    },
    "required": ["scan_summary","overall_severity","attack_paths","top_risks"],
    "additionalProperties": false
  }
}
```

`additionalProperties: false` + `required` on every field means Claude
cannot send half-baked data or invent new fields. The API rejects malformed
output before it ever reaches us.

The user message is just:

```
## ATTACK SURFACE GRAPH
<output of GraphSerializer.serialize()>

## POSTURE FINDINGS
### CRITICAL (3)
- [check_id] title
  Resource: name (type)
  Detail: ...
  Fix: ...
### HIGH (12)
...
```

Findings are grouped by severity so Claude can scan from worst to least-worst.

---

## The Report Models

[report.py](report.py) — pure dataclasses, no business logic.

```
AnalysisReport
├── scan_summary       : str
├── overall_severity   : str   (CRITICAL / HIGH / MEDIUM / LOW)
├── attack_paths       : list[AttackPath]
├── top_risks          : list[str]
└── raw_response       : str   (preserved for debugging if parse fails)

AttackPath
├── entry_point        : str
├── attack_steps       : list[str]   (ordered)
├── blast_radius       : str
├── severity           : str
├── confidence         : str
└── remediation        : list[str]
```

Three renderers — pick the one that fits your downstream:

| Method            | Output                                          |
|-------------------|-------------------------------------------------|
| `to_dict()`       | dict — for further programmatic processing      |
| `to_json(indent)` | JSON string — for API responses, file dumps     |
| `to_markdown()`   | Markdown — for humans, terminals, Slack, PRs    |

---

## CLI Entry Point

```bash
breakbot report scans/scan-20240501-... --format md
breakbot report scans/scan-20240501-... --format json -o report.json
breakbot report scans/scan-20240501-... --format html
```

The `report` subcommand handles the full Phase-4 + Phase-5 pipeline:

```
scan-dir/
├── scan.json     ─┐
├── trail.json    ─┼─► GraphBuilder + TrailOverlay  ─► serialize ─┐
└── posture.json  ─┘                                              │
                                                                  ▼
                                                          SecurityAnalyst
                                                                  │
                                                                  ▼
                                                          report.{md,json,html}
```

---

## Failure Modes

| Failure                              | Behavior                                            |
|--------------------------------------|-----------------------------------------------------|
| Claude returns malformed tool input  | **Cannot happen** — API rejects it before we see it |
| Claude refuses to call the tool      | `RuntimeError` with the actual block types returned |
| `ANTHROPIC_API_KEY` not set          | SDK raises `AuthenticationError` on first call      |
| Anthropic API rate-limited           | SDK auto-retries with exponential backoff (default 2) |
| Graph too big for the context window | Surfaces as a `BadRequestError` from the API; future work to truncate `ALL NODES`/`ALL EDGES` sections, keep paths |

---

## Files

```
brain/
├── analyst.py     SecurityAnalyst — the Claude call
├── report.py      AnalysisReport, AttackPath dataclasses + renderers
├── __init__.py    public API: SecurityAnalyst, AnalysisReport, AttackPath
└── README.md      this file
```

See also: [graph/README.md](../graph/README.md) for what the analyst is reading.
