"""
IRIS MCP Server for Cursor IDE.

This is the shift-left engine. It runs as a local MCP (Model Context Protocol)
server that Cursor connects to. When a developer writes agent code, Cursor
asks IRIS to evaluate it for compliance violations. IRIS responds with:
  1. What the violation is in plain English
  2. The exact fix (corrected code)
  3. Which compliance rule it satisfies

The developer sees the fix inline and approves it with one click.
Think of it like ESLint but for the Colorado AI Act.

Setup:
  pip install iris-security-sdk
  iris mcp start          ← starts this server on localhost:7779
  Then add to Cursor settings (see .cursor/mcp.json)
"""

import json
import asyncio
from pathlib import Path
from typing import Any
from datetime import datetime


# ── MCP tool definitions ──────────────────────────────────────────────────────
# These are the tools Cursor calls when it wants IRIS feedback.

MCP_TOOLS = [
    {
        "name": "iris_check_agent_code",
        "description": (
            "Check Python or TypeScript agent code for IRIS governance violations. "
            "Returns violations with plain-English explanations and suggested fixes. "
            "Call this whenever a developer writes code that creates or calls an AI agent."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "code": {
                    "type": "string",
                    "description": "The agent code to check",
                },
                "file_path": {
                    "type": "string",
                    "description": "Path to the file being edited",
                },
                "framework": {
                    "type": "string",
                    "description": "Compliance framework to check against",
                    "default": "colorado-ai-act",
                },
            },
            "required": ["code"],
        },
    },
    {
        "name": "iris_get_passport_status",
        "description": (
            "Get the governance status of a specific agent. "
            "Returns passport details, compliance check results, and next steps."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "agent_name": {
                    "type": "string",
                    "description": "Name of the agent to check",
                },
            },
            "required": ["agent_name"],
        },
    },
    {
        "name": "iris_suggest_policy",
        "description": (
            "Generate a suggested IRIS policy for agent code. "
            "Returns a policy-intent.md draft and the compiled Cedar policy. "
            "Call this when a developer has written agent code but has no policy file."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "code": {
                    "type": "string",
                    "description": "The agent code to generate policy for",
                },
                "agent_name": {
                    "type": "string",
                    "description": "Name for the agent",
                },
            },
            "required": ["code", "agent_name"],
        },
    },
    {
        "name": "iris_fix_violation",
        "description": (
            "Given a specific IRIS violation, return the corrected code. "
            "The developer can approve the fix with one click in Cursor."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "violation_rule_id": {
                    "type": "string",
                    "description": "The IRIS rule ID (e.g. CO-002, IRIS-XR-001)",
                },
                "code": {
                    "type": "string",
                    "description": "The code that triggered the violation",
                },
                "agent_name": {
                    "type": "string",
                    "description": "Agent name for context",
                },
            },
            "required": ["violation_rule_id", "code"],
        },
    },
    {
        "name": "iris_scan_workspace",
        "description": (
            "Scan the entire workspace for ungoverned agents and policy gaps. "
            "Returns a summary of all agents found, their compliance status, "
            "and prioritized list of actions to take."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspace_path": {
                    "type": "string",
                    "description": "Path to the workspace root",
                },
            },
            "required": [],
        },
    },
]


# ── Tool handlers ─────────────────────────────────────────────────────────────

def handle_check_agent_code(params: dict) -> dict:
    """
    Analyze agent code for compliance violations.
    This is the core feedback loop for Cursor.
    """
    code = params.get("code", "")
    file_path = params.get("file_path", "unknown")
    framework = params.get("framework", "colorado-ai-act")

    violations = []
    suggestions = []

    # Pattern: agent making LLM calls without IRIS decorator
    if any(kw in code for kw in ["openai", "anthropic", "ChatOpenAI", "claude"]):
        if "@agent.guard" not in code and "IrisAgent" not in code:
            violations.append({
                "rule_id": "IRIS-SDK-001",
                "severity": "HIGH",
                "message": (
                    "This code makes LLM API calls without IRIS governance. "
                    "Any agent calling an LLM must be registered with an AgentPassport "
                    "and have its tool calls wrapped with @agent.guard()."
                ),
                "compliance_refs": ["colorado-ai-act:CO-003", "iris:tool-permission"],
                "line_hint": next(
                    (i + 1 for i, l in enumerate(code.splitlines())
                     if any(kw in l for kw in ["openai", "anthropic", "ChatOpenAI", "claude"])),
                    None,
                ),
                "fix": _generate_iris_wrapper(code),
            })

    # Pattern: PII access without data_classification declared
    if any(kw in code for kw in ["pii", "personal_data", "ssn", "email", "phone", "address"]):
        if "data_classification" not in code:
            violations.append({
                "rule_id": "IRIS-DATA-001",
                "severity": "CRITICAL",
                "message": (
                    "This code appears to access personal data but does not declare "
                    "a data_classification. Under the Colorado AI Act, agents handling "
                    "PII must explicitly declare and restrict their data access."
                ),
                "compliance_refs": ["colorado-ai-act:CO-004", "iris:data-classification"],
                "fix": "Add data_classification=DataClassification.PII to your IrisAgent declaration.",
            })

    # Pattern: cross-region data movement
    if any(kw in code for kw in ["cn-north", "china", "cn-northwest", "beijing"]):
        violations.append({
            "rule_id": "IRIS-XR-001",
            "severity": "CRITICAL",
            "message": (
                "This code references a Chinese AWS region. Transferring data "
                "between China and the US violates China PIPL. "
                "IRIS will block this call at runtime in production."
            ),
            "compliance_refs": ["china-pipl:cross-border-transfer"],
            "fix": (
                "Add destination_region to your @agent.guard() decorator. "
                "IRIS will enforce the cross-region policy automatically."
            ),
        })

    # Pattern: high-risk domain with no consent gate
    high_risk_keywords = [
        "loan", "credit", "insurance", "medical", "diagnosis",
        "hiring", "employment", "eviction", "mortgage",
    ]
    if any(kw in code.lower() for kw in high_risk_keywords):
        if "user_consent" not in code and "consent" not in code:
            violations.append({
                "rule_id": "CO-004",
                "severity": "HIGH",
                "message": (
                    "This agent appears to make consequential decisions "
                    "(financial, medical, or employment-related) without a "
                    "consent gate. The Colorado AI Act requires consumers to "
                    "be able to opt out of consequential AI decisions."
                ),
                "compliance_refs": ["colorado-ai-act:CO-004"],
                "fix": (
                    "Add user_consent_logged=True to your @agent.guard() context "
                    "and ensure your application captures explicit user consent "
                    "before calling this agent."
                ),
            })

    # Pattern: no passport registered
    if "def " in code and any(kw in code for kw in ["agent", "llm", "chain", "crew"]):
        if "IrisAgent" not in code and "AgentPassport" not in code:
            suggestions.append({
                "type": "registration",
                "message": (
                    "No IRIS AgentPassport detected. Run the following command "
                    "to register this agent and generate a Colorado AI Act compliant passport:"
                ),
                "command": f"iris register --name my-agent --owner you@company.com --compliance colorado-ai-act",
            })

    return {
        "file": file_path,
        "framework": framework,
        "violations_found": len(violations),
        "violations": violations,
        "suggestions": suggestions,
        "status": "FAIL" if violations else "PASS",
        "timestamp": datetime.utcnow().isoformat(),
    }


def handle_get_passport_status(params: dict) -> dict:
    """Get full governance status for an agent."""
    agent_name = params.get("agent_name", "")
    gov_dir = Path.cwd() / "governance" / "agents" / agent_name
    passport_file = gov_dir / "passport.yaml"

    if not passport_file.exists():
        return {
            "agent": agent_name,
            "status": "NOT_REGISTERED",
            "message": f"No passport found for '{agent_name}'.",
            "next_step": f"iris register --name {agent_name} --compliance colorado-ai-act",
        }

    try:
        import yaml as _yaml
        passport_data = _yaml.safe_load(passport_file.read_text())
        spec = passport_data.get("spec", {})

        violations = []
        if spec.get("is_high_risk_ai") and not spec.get("evidence_vault_id"):
            violations.append({
                "rule_id": "CO-002",
                "severity": "CRITICAL",
                "message": "No impact assessment on file.",
                "fix_command": f"iris compliance assess --agent {agent_name}",
            })
        if not spec.get("intent_ref"):
            violations.append({
                "rule_id": "CO-003",
                "severity": "HIGH",
                "message": "No transparency disclosure (policy-intent.md).",
                "fix_command": f"iris policy compile --agent {agent_name}",
            })

        return {
            "agent": agent_name,
            "status": "COMPLIANT" if not violations else "NON_COMPLIANT",
            "passport": spec,
            "violations": violations,
            "files": {
                "passport": str(passport_file),
                "policy": str(gov_dir / "policy.cedar"),
                "intent": str(gov_dir / "policy-intent.md"),
                "assessment": str(gov_dir / "impact-assessment.md"),
            },
        }
    except Exception as e:
        return {"agent": agent_name, "status": "ERROR", "error": str(e)}


def handle_suggest_policy(params: dict) -> dict:
    """Generate a policy suggestion from agent code."""
    code = params.get("code", "")
    agent_name = params.get("agent_name", "my-agent")

    tools_detected = []
    if "openai" in code or "ChatOpenAI" in code:
        tools_detected.append("openai-api")
    if "anthropic" in code or "claude" in code:
        tools_detected.append("anthropic-api")
    if "requests" in code or "httpx" in code:
        tools_detected.append("external-http")
    if "boto3" in code or "s3" in code.lower():
        tools_detected.append("aws-s3")
    if "postgres" in code.lower() or "mysql" in code.lower() or "database" in code.lower():
        tools_detected.append("database")

    intent_draft = f"""# Policy Intent — {agent_name}

## What this agent does
[Auto-detected from code — edit this description]

## What it is allowed to access
{chr(10).join(f'- {t}' for t in tools_detected) or '- [No tools auto-detected — add them here]'}

## What it must never do
- Access personal data outside approved regions
- Make consequential decisions without user consent logged
- Call any API not listed above

## Compliance notes
This agent operates under the Colorado AI Act (SB 26-189, effective Jan. 1, 2027).
User consent must be logged before any consequential decision.
"""

    return {
        "agent_name": agent_name,
        "tools_detected": tools_detected,
        "intent_draft": intent_draft,
        "next_steps": [
            f"Save the intent draft to: governance/agents/{agent_name}/policy-intent.md",
            f"Then run: iris policy compile --agent {agent_name}",
            f"Then run: iris compliance assess --agent {agent_name}",
        ],
    }


def handle_fix_violation(params: dict) -> dict:
    """Return corrected code for a specific violation."""
    rule_id = params.get("violation_rule_id", "")
    code = params.get("code", "")
    agent_name = params.get("agent_name", "my-agent")

    fixes = {
        "IRIS-SDK-001": {
            "explanation": "Wrap your agent in an IrisAgent and decorate tool calls with @agent.guard()",
            "code_prefix": f"""from iris import IrisAgent, DataClassification

agent = IrisAgent(
    name="{agent_name}",
    owner="your-email@company.com",
    compliance=["colorado-ai-act"],
)

""",
        },
        "CO-002": {
            "explanation": "Run the impact assessment to generate a CO-002-compliant document",
            "command": f"iris compliance assess --agent {agent_name}",
        },
        "CO-003": {
            "explanation": "Compile your policy intent to generate the transparency disclosure",
            "command": f"iris policy compile --agent {agent_name}",
        },
        "CO-004": {
            "explanation": "Add user_consent_logged=True to your guard decorator context",
            "code_snippet": "@agent.guard(tool=\"your-tool\", action=\"call\", user_consent_logged=True)",
        },
        "IRIS-XR-001": {
            "explanation": "Declare the destination region so IRIS can enforce cross-region policy",
            "code_snippet": "@agent.guard(tool=\"storage\", action=\"write\", data_region=\"us-east-1\", destination_region=\"us-east-1\")",
        },
    }

    fix = fixes.get(rule_id, {
        "explanation": f"No auto-fix available for {rule_id}. Run: iris compliance check for guidance.",
    })

    return {
        "rule_id": rule_id,
        "fix": fix,
        "approved": False,
    }


def handle_scan_workspace(params: dict) -> dict:
    """Scan workspace for ungoverned agents."""
    workspace = Path(params.get("workspace_path", "."))
    gov_dir = workspace / "governance" / "agents"

    agents_found = []
    ungoverned = []

    if gov_dir.exists():
        for passport_file in gov_dir.rglob("passport.yaml"):
            agent_name = passport_file.parent.name
            has_policy = (passport_file.parent / "policy.cedar").exists()
            has_assessment = (passport_file.parent / "impact-assessment.md").exists()
            agents_found.append({
                "name": agent_name,
                "has_passport": True,
                "has_policy": has_policy,
                "has_assessment": has_assessment,
                "compliant": has_policy and has_assessment,
            })

    py_files = list(workspace.rglob("*.py"))
    for f in py_files:
        try:
            content = f.read_text()
            if any(kw in content for kw in ["openai", "anthropic", "LLM", "ChatOpenAI"]):
                if "IrisAgent" not in content:
                    ungoverned.append(str(f.relative_to(workspace)))
        except Exception:
            pass

    return {
        "agents_registered": len(agents_found),
        "agents": agents_found,
        "ungoverned_files": ungoverned,
        "priority_actions": [
            f"Register {len(ungoverned)} ungoverned agent file(s)" if ungoverned else None,
            "Run iris compliance assess for agents missing impact assessments",
            "Run iris policy compile for agents missing Cedar policies",
        ],
    }


def _generate_iris_wrapper(code: str) -> str:
    return '''from iris import IrisAgent, DataClassification

# Add IRIS governance to this agent
agent = IrisAgent(
    name="my-agent",
    owner="your-email@company.com",
    compliance=["colorado-ai-act"],
    is_high_risk_ai=True,  # set True if making consequential decisions
)

# Wrap your tool calls with @agent.guard()
@agent.guard(tool="llm-api", action="call")
def your_agent_function():
    # your existing code here
    pass
'''


# ── MCP Server (stdio transport) ──────────────────────────────────────────────

HANDLERS = {
    "iris_check_agent_code": handle_check_agent_code,
    "iris_get_passport_status": handle_get_passport_status,
    "iris_suggest_policy": handle_suggest_policy,
    "iris_fix_violation": handle_fix_violation,
    "iris_scan_workspace": handle_scan_workspace,
}


async def handle_request(request: dict) -> dict:
    """Handle a single MCP JSON-RPC request."""
    method = request.get("method", "")
    req_id = request.get("id")
    params = request.get("params", {})

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {
                    "name": "iris-mcp",
                    "version": "0.1.0",
                    "description": "IRIS AI Agent Governance — Colorado AI Act compliance in your IDE",
                },
            },
        }

    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {"tools": MCP_TOOLS},
        }

    if method == "tools/call":
        tool_name = params.get("name")
        tool_args = params.get("arguments", {})
        handler = HANDLERS.get(tool_name)

        if not handler:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": f"Unknown tool: {tool_name}"},
            }

        try:
            result = handler(tool_args)
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": json.dumps(result, indent=2)}]
                },
            }
        except Exception as e:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32603, "message": str(e)},
            }

    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": -32601, "message": f"Method not found: {method}"},
    }


async def run_stdio_server():
    """Run the MCP server over stdio (Cursor's transport)."""
    import sys
    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    await asyncio.get_event_loop().connect_read_pipe(lambda: protocol, sys.stdin)
    writer_transport, writer_protocol = await asyncio.get_event_loop().connect_write_pipe(
        asyncio.BaseProtocol, sys.stdout
    )

    while True:
        try:
            line = await reader.readline()
            if not line:
                break
            request = json.loads(line.decode())
            response = await handle_request(request)
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()
        except Exception:
            break


def start():
    """Entry point for: iris mcp start"""
    asyncio.run(run_stdio_server())


if __name__ == "__main__":
    start()
